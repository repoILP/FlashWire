/*
  udpsdl_fixed.c - UDP Symbolic Deduplication Layer (corrigido)
  Envia arquivos com muita repetição usando pouca banda.

  Compila: gcc -O2 -std=c11 -Wall -o udpsdl_fixed udpsdl_fixed.c
  Uso:
    Servidor: ./udpsdl_fixed server arquivo.bin 127.0.0.1 5000
    Cliente:  ./udpsdl_fixed client 5000 arquivo_recebido.bin
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <endian.h>

/* ==================== CONFIGURAÇÃO ==================== */
#define CHUNK_SIZE     4096
#define DICT_MIN_FREQ  2
#define MAX_UDP_PAYLOAD 1200
#define VERSION_BYTE   0x01
#define MAX_RETRIES    15
#define ACK_TIMEOUT_SEC 3
/* ===================================================== */

/* Tipos de pacote */
#define PT_CATALOG 1
#define PT_INSTR   2
#define PT_ACK     3
#define PT_DONE    4

/* Instruções */
#define OP_EMIT_ID  1
#define OP_EMIT_RAW 2

/* ==================== SHA-256 CORRETO (padrão público) ==================== */
#define ROTR(x,n) (((x)>>(n))|((x)<<(32-(n))))
#define CH(x,y,z) (((x)&(y))^(~(x)&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t data[64];
    int datalen;
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_transform(SHA256_CTX *ctx, const uint8_t *data) {
    uint32_t a,b,c,d,e,f,g,h,i,t1,t2,m[64];
    for (i=0; i<16; ++i)
        m[i] = (data[i*4]<<24)|(data[i*4+1]<<16)|(data[i*4+2]<<8)|data[i*4+3];
    for (; i<64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=ctx->state[0]; b=ctx->state[1]; c=ctx->state[2]; d=ctx->state[3];
    e=ctx->state[4]; f=ctx->state[5]; g=ctx->state[6]; h=ctx->state[7];
    for (i=0; i<64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    ctx->state[0]+=a; ctx->state[1]+=b; ctx->state[2]+=c; ctx->state[3]+=d;
    ctx->state[4]+=e; ctx->state[5]+=f; ctx->state[6]+=g; ctx->state[7]+=h;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i=0; i<len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += ctx->datalen * 8;
    for (i=0; i<8; ++i)
        ctx->data[63-i] = ctx->bitlen >> (i*8);
    sha256_transform(ctx, ctx->data);
    for (i=0; i<32; ++i)
        hash[i] = ctx->state[i/4] >> ((3-(i%4))*8);
}
/* ===================================================================== */

/* Tabela de hash simples */
#define HT_SIZE 131072
typedef struct entry {
    uint8_t hash[32];
    uint32_t freq;
    uint32_t id;
    uint8_t *data;
    uint32_t len;
    struct entry *next;
} entry_t;

static entry_t *ht[HT_SIZE] = {0};

static uint32_t hash_idx(const uint8_t *h) {
    uint32_t v;
    memcpy(&v, h, sizeof(uint32_t));
    return v % HT_SIZE;
}

static entry_t *find(const uint8_t *h) {
    for (entry_t *e = ht[hash_idx(h)]; e; e = e->next)
        if (!memcmp(e->hash, h, 32)) return e;
    return NULL;
}

static entry_t *insert(const uint8_t *h, const uint8_t *data, uint32_t len) {
    entry_t *e = calloc(1, sizeof(entry_t));
    memcpy(e->hash, h, 32);
    e->freq = 1;
    e->data = NULL;
    e->len = 0;
    if (len) {
        e->data = malloc(len);
        memcpy(e->data, data, len);
        e->len = len;
    }
    uint32_t idx = hash_idx(h);
    e->next = ht[idx];
    ht[idx] = e;
    return e;
}

static void ht_clear(void) {
    for (int i=0; i<HT_SIZE; i++) {
        entry_t *e = ht[i];
        while (e) {
            entry_t *n = e->next;
            free(e->data);
            free(e);
            e = n;
        }
        ht[i] = NULL;
    }
}

/* Envio segmentado */
static int send_segments(int sock, struct sockaddr_in *peer, uint8_t type,
                         const uint8_t *data, size_t len) {
    size_t nseg = (len + MAX_UDP_PAYLOAD - 1) / MAX_UDP_PAYLOAD;
    if (nseg == 0) nseg = 1; /* allow empty payload as single segment */
    for (size_t i=0; i<nseg; i++) {
        size_t off = i * MAX_UDP_PAYLOAD;
        size_t plen = (off + MAX_UDP_PAYLOAD <= len) ? MAX_UDP_PAYLOAD : (len > off ? len - off : 0);
        uint8_t pkt[1500];
        pkt[0] = VERSION_BYTE;
        pkt[1] = type;
        uint32_t ii = (uint32_t)i;
        *(uint32_t*)(pkt+2) = htonl(ii);
        *(uint32_t*)(pkt+6) = htonl((uint32_t)nseg);
        *(uint16_t*)(pkt+10) = htons((uint16_t)plen);
        if (plen) memcpy(pkt+12, data+off, plen);
        size_t sendlen = 12 + plen;
        if (sendto(sock, pkt, sendlen, 0, (struct sockaddr*)peer, sizeof(*peer)) < 0)
            return -1;
        usleep(500); /* tiny pacing */
    }
    return 0;
}

/* Recebe e reagrupa (com timeout) */
static int recv_full(int sock, uint8_t **out, size_t *outlen, uint8_t want_type,
                     struct sockaddr_in *src) {
    uint8_t buf[1600];
    struct sockaddr_in from;
    socklen_t flen = sizeof(from);
    fd_set fds;

    while (1) {
        struct timeval tv = {ACK_TIMEOUT_SEC, 0};
        FD_ZERO(&fds); FD_SET(sock, &fds);
        int r = select(sock+1, &fds, NULL, NULL, &tv);
        if (r <= 0) return -1;

        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &flen);
        if (n < 12 || buf[0] != VERSION_BYTE) continue;
        if (src && memcmp(&from, src, sizeof(from)) != 0) continue;

        if (buf[1] == PT_ACK || buf[1] == PT_DONE) {
            if (src) *src = from;
            return (buf[1] == want_type) ? 1 : 0;
        }

        if (buf[1] != want_type) continue;

        uint32_t idx = ntohl(*(uint32_t*)(buf+2));
        uint32_t total = ntohl(*(uint32_t*)(buf+6));
        uint16_t plen = ntohs(*(uint16_t*)(buf+10));

        if (*out == NULL) {
            /* aloca buffer para todos os segmentos */
            size_t allocsz = (size_t)total * MAX_UDP_PAYLOAD;
            *out = malloc(allocsz);
            if (!*out) return -1;
            memset(*out, 0, allocsz);
            if (src) *src = from;
        }

        if (!*out) continue;

        memcpy(*out + (size_t)idx * MAX_UDP_PAYLOAD, buf+12, plen);

        if (idx + 1 == total) {
            *outlen = (idx * (size_t)MAX_UDP_PAYLOAD) + plen;
            return 0;
        }
    }
}

/* ============================= SERVIDOR ============================= */
int server_main(const char *path, const char *ip, int port) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("open"); return 1; }
    struct stat st; stat(path, &st);
    uint64_t fsize = st.st_size;
    printf("[server] enviando %s (%"PRIu64" bytes)\n", path, fsize);

    /* Passo 1: ler e contar frequência */
    uint8_t *chunk = malloc(CHUNK_SIZE);
    uint64_t nchunks = (fsize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    typedef struct { uint8_t hash[32]; } chunkinfo_t;
    chunkinfo_t *chunks = calloc((size_t)nchunks, sizeof(chunkinfo_t));

    for (uint64_t i=0; i<nchunks; i++) {
        size_t r = fread(chunk, 1, CHUNK_SIZE, f);
        if (r == 0) break;
        SHA256_CTX ctx; sha256_init(&ctx);
        sha256_update(&ctx, chunk, r);
        sha256_final(&ctx, chunks[i].hash);
        entry_t *e = find(chunks[i].hash);
        if (e) e->freq++; else insert(chunks[i].hash, NULL, 0);
    }
    rewind(f);

    /* Passo 2: atribuir IDs e guardar dados só dos repetidos */
    uint32_t next_id = 1;
    for (int i=0; i<HT_SIZE; i++) {
        for (entry_t *e=ht[i]; e; e=e->next) {
            if (e->freq >= DICT_MIN_FREQ) {
                e->id = next_id++;
                /* localizar um bloco com esse hash e ler seus dados */
                for (uint64_t j=0; j<nchunks; j++) {
                    if (memcmp(chunks[j].hash, e->hash, 32)==0) {
                        fseek(f, (off_t)j*CHUNK_SIZE, SEEK_SET);
                        size_t r = fread(chunk, 1, CHUNK_SIZE, f);
                        free(e->data);
                        e->data = malloc(r);
                        memcpy(e->data, chunk, r);
                        e->len = r;
                        break;
                    }
                }
            }
        }
    }

    /* Montar catálogo */
    size_t catalog_cap = 10*1024*1024;
    uint8_t *catalog = malloc(catalog_cap);
    uint8_t *p = catalog;
    uint32_t ndict = htonl(next_id-1);
    memcpy(p, &ndict, 4); p += 4;
    for (int i=0; i<HT_SIZE; i++) {
        for (entry_t *e=ht[i]; e; e=e->next) {
            if (e->id) {
                uint32_t tmp = htonl(e->id); memcpy(p, &tmp, 4); p+=4;
                tmp = htonl(e->len); memcpy(p, &tmp, 4); p+=4;
                memcpy(p, e->hash, 32); p+=32;
                memcpy(p, e->data, e->len); p+=e->len;
            }
        }
    }
    uint64_t tmp64 = htobe64(fsize); memcpy(p, &tmp64, 8); p+=8;
    uint32_t tmp32 = htonl(CHUNK_SIZE); memcpy(p, &tmp32, 4); p+=4;

    /* Socket e envio */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in peer = {0};
    peer.sin_family = AF_INET;
    peer.sin_port = htons(port);
    inet_pton(AF_INET, ip, &peer.sin_addr);

    int ok = 0;
    for (int try=0; try<MAX_RETRIES && !ok; try++) {
        send_segments(sock, &peer, PT_CATALOG, catalog, p-catalog);
        /* aguardar ACK vindo do peer */
        if (recv_full(sock, NULL, NULL, PT_ACK, &peer) == 1) ok=1;
    }
    if (!ok) { printf("sem ACK do catálogo\n"); return 1; }

    /* Montar stream de instruções */
    size_t stream_cap = (size_t)fsize/4 + 1024;
    uint8_t *stream = malloc(stream_cap);
    uint8_t *q = stream;
    fseek(f, 0, SEEK_SET);
    for (uint64_t i=0; i<nchunks; i++) {
        size_t r = fread(chunk, 1, CHUNK_SIZE, f);
        SHA256_CTX ctx; sha256_init(&ctx);
        sha256_update(&ctx, chunk, r);
        uint8_t h[32]; sha256_final(&ctx, h);
        entry_t *e = find(h);
        if (e && e->id) {
            *q++ = OP_EMIT_ID;
            uint32_t idn = htonl(e->id);
            memcpy(q, &idn, 4); q+=4;
        } else {
            *q++ = OP_EMIT_RAW;
            uint32_t len = htonl((uint32_t)r);
            memcpy(q, &len, 4); q+=4;
            memcpy(q, chunk, r); q+=r;
        }
    }

    send_segments(sock, &peer, PT_INSTR, stream, q-stream);
    send_segments(sock, &peer, PT_DONE, NULL, 0);  /* sinal de fim */

    printf("[server] concluído! compressão: %.1fx\n",
           (double)fsize / (double)((p-catalog) + (q-stream)));

    free(chunk); free(chunks); free(catalog); free(stream);
    ht_clear(); close(sock);
    return 0;
}

/* ============================= CLIENTE ============================= */
int client_main(int port, const char *outpath) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in me = {0};
    me.sin_family = AF_INET;
    me.sin_port = htons(port);
    me.sin_addr.s_addr = INADDR_ANY;
    bind(sock, (struct sockaddr*)&me, sizeof(me));
    printf("[client] escutando na porta %d\n", port);

    uint8_t *cat = NULL, *instr = NULL;
    size_t catlen=0, instrlen=0;
    struct sockaddr_in server_addr = {0};

    if (recv_full(sock, &cat, &catlen, PT_CATALOG, &server_addr) != 0)
        { printf("falha catálogo\n"); return 1; }
    uint8_t ack[2] = {VERSION_BYTE, PT_ACK};
    sendto(sock, ack, 2, 0, (struct sockaddr*)&server_addr, sizeof(server_addr));

    uint8_t *p = cat;
    uint32_t ndict = ntohl(*(uint32_t*)p); p+=4;
    uint8_t **dict = calloc((size_t)ndict+1, sizeof(uint8_t*));
    uint32_t *dlen = calloc((size_t)ndict+1, sizeof(uint32_t));

    for (uint32_t i=0; i<ndict; i++) {
        uint32_t id = ntohl(*(uint32_t*)p); p+=4;
        uint32_t len = ntohl(*(uint32_t*)p); p+=4;
        p += 32;  /* hash ignorado no cliente */
        dict[id] = malloc(len);
        memcpy(dict[id], p, len);
        dlen[id] = len;
        p += len;
    }
    uint64_t fsize = be64toh(*(uint64_t*)p); p+=8;
    printf("[client] arquivo esperado: %"PRIu64" bytes, dicionário: %u blocos\n", fsize, ndict);

    if (recv_full(sock, &instr, &instrlen, PT_INSTR, &server_addr) != 0)
        { printf("falha stream\n"); return 1; }
    if (recv_full(sock, NULL, NULL, PT_DONE, &server_addr) != 1)
        { printf("sem sinal de fim\n"); return 1; }

    FILE *out = fopen(outpath, "wb");
    uint8_t *q = instr;
    size_t remain = instrlen;
    while (remain > 0) {
        uint8_t op = *q++; remain--;
        if (op == OP_EMIT_ID) {
            uint32_t id = ntohl(*(uint32_t*)q); q+=4; remain-=4;
            fwrite(dict[id], 1, dlen[id], out);
        } else if (op == OP_EMIT_RAW) {
            uint32_t len = ntohl(*(uint32_t*)q); q+=4; remain-=4;
            fwrite(q, 1, len, out);
            q += len; remain -= len;
        } else {
            /* desconhecido: abortar */
            fprintf(stderr, "op desconhecida: %u\n", (unsigned)op);
            break;
        }
    }
    fclose(out);
    printf("[client] arquivo salvo como %s - OK!\n", outpath);

    free(cat); free(instr);
    for (uint32_t i=1; i<=ndict; i++) if (dict[i]) free(dict[i]);
    free(dict); free(dlen);
    close(sock);
    return 0;
}

/* ============================= MAIN ============================= */
int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Uso:\n");
        printf("  Servidor: %s server <arquivo> <ip_cliente> <porta>\n", argv[0]);
        printf("  Cliente:  %s client <porta> <arquivo_saida>\n", argv[0]);
        return 1;
    }

    if (!strcmp(argv[1], "server")) {
        if (argc != 5) return 1;
        return server_main(argv[2], argv[3], atoi(argv[4]));
    }
    if (!strcmp(argv[1], "client")) {
        if (argc != 4) return 1;
        return client_main(atoi(argv[2]), argv[3]);
    }
    return 1;
}
