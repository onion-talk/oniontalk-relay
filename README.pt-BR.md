# 🧅 OnionTalk — Servidor Federado (Relay Node)

Este pacote contém tudo o que você precisa para rodar um **Nó Federado do OnionTalk** na sua própria casa (PC, Mini-PC, Raspberry Pi, NAS ou VPS) e fortalecer a malha descentralizada de mensagens criptografadas.

---

## 💡 Por que qualquer pessoa pode rodar em casa?

* **Zero Portas Abertas no Roteador (Funciona em CGNAT)**: Como o nó opera exclusivamente como um **Tor Hidden Service v3 (`.onion`)**, o container abre conexões de saída para a rede Tor. Você **não** precisa configurar redirecionamento de portas (*Port Forwarding*), nem ter IP fixo ou DNS público.
* **Zero-Knowledge & Apenas em Memória RAM**: O servidor atua apenas como correio cego (*store-and-forward*) de envelopes já criptografados e os apaga da memória RAM imediatamente após o recebimento (`ACK`) pelo destinatário. Nenhum histórico de conversa é gravado em disco.
* **Descoberta Automática (Gossip Mesh)**: Ao iniciar, seu servidor gera automaticamente uma identidade `.onion` exclusiva e se anuncia para os **Nós Semente (Seed Nodes)** da rede. Em poucos segundos, todos os outros servidores da malha passam a conhecer e sincronizar com o seu nó.

---

## 📦 Estrutura da Pasta

```text
server/
├── docker-compose.yml   # Container único All-in-One (Tor 0.4.9.14 oficial embutido + Relay API)
├── Dockerfile           # Imagem Debian Bookworm + Tor Project 0.4.9.14 + Gunicorn
├── entrypoint.sh        # Inicializa /data/hidden_service (0700), sobe o daemon Tor v3 e watchdog
├── relay.py             # Motor de roteamento, fila em RAM e Gossip Mesh
├── requirements.txt     # Dependências mínimas (Flask, Requests+SOCKS, Gunicorn)
└── README.md            # Este guia de instalação e operação
```

---

## 🛠️ Pré-requisitos

Você só precisa ter instalado na máquina:
* **Docker** e **Docker Compose**
  * **Windows / macOS**: [Docker Desktop](https://www.docker.com/products/docker-desktop/)
  * **Linux (Ubuntu / Debian / Raspberry Pi OS)**:
    ```bash
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    ```

---

## 🚀 What's New in `v1.5.4` (`versionCode = 48` / Build 48) & Relay Node `v1.5.2` (`Build 11`) & Mesh `v=31` — Post-Quantum Hybrid Encryption (`ML-KEM-768`), Dual Warm Socket Pool (~1.13s E2E), S/Kademlia XOR Routing & GossipSub v1.2

- **📦 Direct Signed APK Downloads (`v1.5.4` — Latest Release Build 48)**:
  - **Main Messenger APK (`org.oniontalk.messenger` `v1.5.4` Build 48)**: [**Download `OnionTalk-v1.5.4.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.5.4/OnionTalk-v1.5.4.apk) (`SHA-256: 18339d0f2110ab49ac7c971d32fb8bf2fedf483b328af6698309a3567b275d5a`)
  - **Standalone Android Relay Node APK (`org.oniontalk.relaynode` `v1.5.2` Build 11)**: [**Download `OnionTalk-RelayNode-v1.4.3.apk`**](https://github.com/onion-talk/oniontalk-demo/releases/download/v1.4.4-demo/OnionTalk-RelayNode-v1.4.3.apk) (`SHA-256: f03069d9c8788a18224bb15327d547c40c55d2ee224d962fbb9eddde087666b0`)
- **🛡️ Key Cryptographic & P2P Mesh Breakthroughs in `v1.5.4` (`Build 48`)**:
  1. **Hybrid Post-Quantum Cryptography (`__ENC_PQC_KYBER768_X25519_V3__`)**: Combines classical **Dual X25519 ECDH** with **NIST FIPS 203 ML-KEM-768 (`Kyber-768`)** key encapsulation via `HKDF-SHA256` + `ChaCha20-Poly1305 AEAD` + `Ed25519` outer envelope signatures to protect against *Harvest Now, Decrypt Later* quantum adversaries.
  2. **Ultra-Fast E2E Delivery (`1.139s – 1.244s`, avg `1.20s`)**: Upgraded **Dual Warm Socket Pool** (`minWarmSockets = 2` per `.onion` gateway, `70s/75s` Keep-Alive) achieving **100% pre-warmed Tor circuit reuse (`0ms` SOCKS5 handshake)** alongside a `250ms` speculative *Hedged Send*.
  3. **S/Kademlia XOR Distance Routing & Blinded Poller Affinity (`v=27`)**: All 20 global `.onion` v3 relays (`v=31`) now route by XOR distance (`SHA-256(peer_onion) ^ SHA-256(recipient_hash)`) with zero-knowledge RAM-only rendezvous affinity (`active_pollers`, `TTL 90s`, zero logs).
  4. **GossipSub v1.2 `IHAVE` / `IDONTWANT` Deduplication**: Relays announce `POST /gossip/ihave` metadata before forwarding payloads `> 1024 bytes`, cutting redundant Tor mesh bandwidth by **~70%**.
  5. **Continuous `10s–12s` Long-Polling & Mandatory `SHA-256` Media Integrity**: Eliminates dead intervals between poll cycles and verifies `SHA-256` Merkle hashes on all voice notes, images, and attachments prior to rendering.

---
## 🚀 Passo a Passo: Subindo seu Servidor (1 Comando)

Abra o terminal (PowerShell no Windows ou Bash no Linux/macOS) dentro desta pasta `server` e execute:

```bash
docker compose up -d --build
```

### O que acontece automaticamente nos primeiros 30 a 60 segundos:
1. O container único **`oniontalk-relay`** inicia o daemon Tor oficial embutido (`0.4.9.14`) com permissões `0700` automáticas e gera o par de chaves criptográficas Ed25519 do seu novo endereço `.onion` v3 (salvo no volume persistente `oniontalk_data`).
2. O mesmo container sobe a API de mensagens na porta `8080` e mantém um *watchdog* interno supervisionando o processo Tor.
3. O loop de *Auto-Discovery* lê o seu novo endereço `.onion` e faz o *handshake* automático com os nós sementes da malha (`BOOTSTRAP_SEEDS`), integrando seu servidor à federação global do OnionTalk.

---

## 🔍 Como Ver o Endereço `.onion` e o Status do seu Nó

### 1. Consultar a Saúde e o Endereço `.onion` do seu Servidor

No **Linux / macOS**:
```bash
curl http://localhost:8080/health
```

No **Windows (PowerShell)**:
```powershell
Invoke-RestMethod http://localhost:8080/health
```

**Exemplo de resposta quando o nó já está sincronizado na malha:**
```json
{
  "status": "healthy",
  "domain": "seu_endereco_gerado_automaticamente_56_chars.onion",
  "peers_count": 4,
  "total_nodes": 5,
  "queued_messages": 0,
  "active_inboxes": 0,
  "messages_received": 12,
  "messages_routed": 48,
  "acks_processed": 12,
  "uptime_seconds": 340
}
```
> **Nota**: Na primeira inicialização, o Tor pode levar de **30 a 90 segundos** para construir os circuitos iniciais até que `peers_count` suba para `4` (ou mais).

### 2. Listar todos os Servidores (Peers) Conectados na Malha

No **Linux / macOS**:
```bash
curl http://localhost:8080/api/v1/peers/list
```

No **Windows (PowerShell)**:
```powershell
Invoke-RestMethod http://localhost:8080/api/v1/peers/list
```

### 3. Acompanhar os Logs em Tempo Real

```bash
docker compose logs -f
```
Você verá mensagens como:
* `[*] [NODE-ID] Identidade .onion estabelecida: xxxx...onion`
* `[*] [MESH-SYNC] Conectado à malha via onion4zr3bsdeael... (4 peers ativos)`
* `[*] [GOSSIP-SYNC-OK] Replicado para peer: ...`

---

## ⚙️ Configurações Opcionais

Caso a porta `8080` já esteja em uso na sua máquina, você pode escolher outra porta local sem afetar a comunicação Tor (que sempre usa a porta virtual `80` dentro da rede `.onion`):

No **Linux / macOS**:
```bash
RELAY_PORT=8090 docker compose up -d
```

No **Windows (PowerShell)**:
```powershell
$env:RELAY_PORT="8090"; docker compose up -d
```

---

## 💾 Backup da Identidade `.onion` do seu Servidor

A chave privada do endereço `.onion` do seu servidor fica salva automaticamente no volume Docker chamado `oniontalk_data` (`/data/hidden_service`).
* Se você reiniciar o computador ou rodar `docker compose restart`, **o seu endereço `.onion` continua o mesmo**.
* **Atenção**: Evite rodar `docker compose down -v` (com a flag `-v`), pois isso apaga o volume `oniontalk_data` e fará o Tor gerar um novo endereço `.onion` na próxima subida.

---

## 🛑 Comandos Úteis de Manutenção

| Ação | Comando |
| :--- | :--- |
| **Iniciar / Atualizar servidor** | `docker compose up -d --build` |
| **Ver status dos containers** | `docker compose ps` |
| **Ver logs em tempo real** | `docker compose logs -f` |
| **Reiniciar o servidor** | `docker compose restart` |
| **Parar o servidor (mantendo a chave `.onion`)** | `docker compose stop` |

---

## ⚠️ Legal Disclaimers, Limitation of Liability & Sovereign Terms of Use (`v1.5.0`)

1. **"AS IS" Open-Source Provision & Cryptographic Research Purpose**: OnionTalk (`org.oniontalk.messenger`), OnionTalk Relay Node (`org.oniontalk.relaynode`), and the Desktop/Web Container (`oniontalk-web`) are distributed strictly **"AS IS"**, without warranties of any kind under the MIT License, as cryptographic engineering and digital privacy technology (`Privacy by Design`).
2. **Irreversible Zero-Knowledge Custody (No Password Recovery)**: Because OnionTalk operates without central servers, user accounts, emails, or phone numbers, **the developers cannot recover forgotten vault passwords, restore lost private keys, or reverse the 5-Strike Anti-Coercion Wipe (`DoD 5220.22-M`) or Synchronized Bilateral Burn (`🔥`)**. Users are solely responsible for safeguarding their local credentials and backups.
3. **Blind Common-Carrier Relay Safe Harbor**: Federated `.onion` v3 relay nodes act strictly as **blind, non-custodial encrypted envelope routers**. Relays possess neither the private `X25519` keys nor the post-quantum `ML-KEM-768` decapsulation keys required to inspect, filter, or modify message contents, and expose only deterministic synthetic topology coordinates (`Zero IP / Zero Cloud Provider Leak`).
4. **Lawful Use & User Responsibility**: Users assume full and exclusive legal responsibility for their use of the software in their respective jurisdictions. Using OnionTalk for unlawful activities is strictly prohibited by the project's terms of use.
5. **Non-Affiliation**: OnionTalk is an independent open-source project and is not affiliated with, endorsed by, or sponsored by *The Tor Project, Inc.*
