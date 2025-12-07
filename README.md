# UDPSDL — Protocolo UDP com Deduplicação de Blocos

UDPSDL (UDP Segment Deduplication Layer) é um protocolo experimental construído sobre UDP, projetado para transmitir arquivos grandes de forma eficiente usando deduplicação por blocos e segmentação confiável.

Ele reduz drasticamente o volume de dados enviado quando existem blocos repetidos, enviando apenas **metadados (catálogo)** e **referências** para blocos já conhecidos.

---

## 📌 Funcionalidades Principais

* Divisão de arquivos em blocos fixos de 4096 bytes.
* Cálculo de hash SHA-256 para cada bloco.
* Deduplicação automática:

  * Blocos repetidos são enviados apenas uma vez.
  * O restante é reconstruído no cliente através de um stream de instruções.
* Segmentação de datagramas UDP com ordenação e reagrupamento.
* Catálogo confiável com retransmissão.
* Construção final do arquivo exatamente igual ao original.

---

## 📁 Estrutura do Protocolo

O envio ocorre em **três etapas**:

### 1. Catálogo

O servidor envia uma lista com todos os hashes SHA-256 dos blocos do arquivo.
O cliente usa isso para identificar blocos repetidos e reconstruir o arquivo localmente.

### 2. Dicionário

O servidor envia apenas os blocos únicos do arquivo.

### 3. Stream de Instruções

O servidor envia uma sequência compacta de IDs indicando a ordem dos blocos no arquivo final.

---

## 🚀 Como Compilar

No Linux:

```bash
gcc -O2 -std=c11 -Wall -o udpsdl_fixed udpsdl_fixed.c -lpthread -lm
```

---

## ▶️ Como Usar

### Servidor

```bash
./udpsdl_fixed server arquivo.bin
```

Transmite `arquivo.bin` ao cliente.

### Cliente

```bash
./udpsdl_fixed client 127.0.0.1 arquivo_recebido.bin
```

Recebe o arquivo e o reconstrói localmente.

---

## ⚙️ Variáveis Importantes

| Nome          | Descrição                                |
| ------------- | ---------------------------------------- |
| `CHUNK_SIZE`  | Tamanho do bloco (4096 bytes por padrão) |
| `CAT_RETRIES` | Tentativas de retransmissão do catálogo  |
| `MAX_PACKET`  | MTU de trabalho (1300 bytes)             |

---

## 📡 Performance Estimada

Para um arquivo de **10 GB**, tempo típico:

* SSD rápido: 5–20 s para hash e deduplicação.
* Envio em rede gigabit: 1–2 minutos sem dedup, segundos se repetido.
* HDD lento: até 1 minuto na preparação.

(Dados detalhados podem ser ajustados conforme seu hardware.)

---

## 🛠️ Requisitos

* Linux (biblioteca `<endian.h>`).
* Suporte a POSIX sockets.

---

## ⚠️ Status

Este protocolo é **experimental** e serve para estudo técnico.
Não possui verificação robusta de integridade além do SHA-256 de bloco.

---

## 📬 Suporte

Se quiser:

* uma versão **multithread** para hash,
* compressão adicional,
* retransmissão seletiva (ARQ),
* handshake mais confiável ou versões para Windows,

é só pedir.
# FlashWire
