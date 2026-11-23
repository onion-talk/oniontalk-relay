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
oniontalk-relay/
├── Cargo.toml           # Manifesto Rust (Tokio, Axum, DashMap, Ed25519-dalek, Sha2/Sha3)
├── Cargo.lock           # Grafo de dependências travado determinístico
├── docker-compose.yml   # Container único All-in-One (Tor 0.4.9.14 oficial embutido + Rust Relay API)
├── Dockerfile           # Build multi-stage Rust 1.85 + Debian Bookworm + Tor Project 0.4.9.14
├── entrypoint.sh        # Inicializa /data/hidden_service (0700), sobe o daemon Tor v3 e o binário Rust
├── docs/
│   ├── PROTOCOL.md      # Especificação oficial do protocolo ENVELOPE_V3 (consolidada de oniontalk-protocol)
│   └── MANIFESTO.md     # Manifesto arquitetural e engenharia anti-censura
├── src/
│   ├── main.rs          # Motor de roteamento em RAM (DashMap Zero-GIL), GossipSub v1.2 e Stream de Voz
│   ├── crypto.rs        # Verificação Ed25519 ENVELOPE_V3, travas SHA-256 ACK e proteção anti-replay
│   ├── founder.rs       # Offline Root CA PKI, listas de revogação otcrl1:, FounderPass e vouchers de nó
│   └── geo.rs           # Topologia federada e metadados da malha
└── README.md            # Guia de instalação e operação
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

## 🚀 Release Oficial Atual & Malha Soberana em Rust — `ENVELOPE_V3` Pós-Quântico, Container Non-Root `UID 10014` & Malha Global Tor v3

- **📦 Downloads Diretos Assinados, Especificação & Imagens Oficiais (Sempre Sincronizados na Última Release)**:
  - **📜 Especificação do Protocolo & Manifesto**: [**`docs/PROTOCOL.md`**](./docs/PROTOCOL.md) · [**`docs/MANIFESTO.md`**](./docs/MANIFESTO.md) *(consolidados aqui após o arquivamento de `oniontalk-protocol`)*
  - **Main Messenger APK (`org.oniontalk.messenger`)**: [**Download `OnionTalk.apk` (latest)**](https://github.com/onion-talk/oniontalk-demo/releases/latest/download/OnionTalk.apk) ![Latest Messenger Release](https://img.shields.io/github/v/release/onion-talk/oniontalk-demo?style=flat-square&label=release&color=00E5FF) ([`SHA256SUMS.txt`](https://github.com/onion-talk/oniontalk-demo/releases/latest/download/SHA256SUMS.txt))
  - **Standalone Android Relay Node APK (`org.oniontalk.relaynode`)**: [**Download `OnionTalk-RelayNode.apk` (latest)**](https://github.com/onion-talk/oniontalk-relay/releases/latest/download/OnionTalk-RelayNode.apk) ![Latest Relay Release](https://img.shields.io/github/v/release/onion-talk/oniontalk-relay?style=flat-square&label=release&color=00E676) ([`SHA256SUMS.txt`](https://github.com/onion-talk/oniontalk-relay/releases/latest/download/SHA256SUMS.txt))
  - **🦀 Container Oficial Relay Rust (`oniontalk-relay-rs`)**: [**`eriktonon/oniontalk:latest`**](https://hub.docker.com/r/eriktonon/oniontalk) ![Docker tag](https://img.shields.io/docker/v/eriktonon/oniontalk?sort=semver&label=tag&style=flat-square) (`UID 10014` non-root, `--cap-drop=ALL`, `tini`, `IntroDoS`, Tor 0.4.9 Equi-X PoW).

> **🔒 Aviso sobre o Código-Fonte (Disclaimer)**: Este servidor Relay em Rust (`oniontalk-relay`) e a especificação do protocolo [`ENVELOPE_V3`](./docs/PROTOCOL.md) são **open-source (MIT)**. O código-fonte dos aplicativos clientes (`org.oniontalk.messenger`, `onion-talk-web` e iOS) encontra-se **bloqueado/fechado temporariamente** durante o ciclo atual de hardening criptográfico e estabilização pré-auditoria.

- **🛡️ Pilares Criptográficos & Roteamento P2P (`ENVELOPE_V3` • Hybrid PQC • Zero-Leak CI Verified)**:
  1. **Hybrid Post-Quantum Cryptography (`__ENC_X25519_CHACHA20_V3__` + `ML-KEM-768`)**: Combina **Dual X25519 ECDH** com **NIST FIPS 203 ML-KEM-768 (`Kyber-768`, `OT_PQC_CAPSULE_V2`)** via `HKDF-SHA256` + `ChaCha20-Poly1305 AEAD` + assinaturas `Ed25519` com vínculo autenticado de `msgId`, `timestamp` e `ack_lock`.
  2. **Ultra-Fast E2E Delivery (`1.13s – 1.24s`)**: **Dual Warm Socket Pool** (`minWarmSockets = 2` por gateway `.onion`, `0ms` de handshake SOCKS5) aliado a *Hedged Send* especulativo em `250ms`.
  3. **S/Kademlia XOR Distance Routing, Blinded Poller Affinity & Equi-X PoW**: Os nós `.onion` v3 da malha global roteiam por distância XOR (`SHA-256(peer_onion) ^ SHA-256(recipient_hash)`) com afinidade cega em RAM (`active_pollers`, `TTL 90s`, zero logs) e defesa anti-DoS **Tor 0.4.9 Equi-X PoW**.
  4. **GossipSub v1.2 `IHAVE` / `IDONTWANT` Deduplication**: Os relays anunciam metadados `POST /api/v1/messages/ihave` antes de encaminhar payloads `> 1024 bytes`, reduzindo o tráfego redundante na malha Tor em **~70%**.
  5. **Offline Root CAs (`otcrl1:`) & Mandatory `SHA-256` Media Integrity**: Governança por raízes offline pinadas com listas assinadas de revogação `otcrl1:` e verificação de hashes Merkle `SHA-256` em áudios, imagens e anexos antes da renderização.

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

## ⚠️ Legal Disclaimers, Limitation of Liability & Sovereign Terms of Use

1. **"AS IS" Provision, Open-Source Relay & Temporarily Restricted Client Source**: Este servidor Relay em Rust (`oniontalk-relay`) e a especificação do protocolo [`ENVELOPE_V3`](./docs/PROTOCOL.md) são open-source sob licença MIT. O código-fonte dos aplicativos clientes (`org.oniontalk.messenger`, `onion-talk-web` e iOS) encontra-se **bloqueado/fechado temporariamente** durante a fase atual de hardening e estabilização pré-auditoria. Todos os binários e containers são distribuídos estritamente **"AS IS"**, sem garantias de qualquer tipo, como tecnologia de engenharia criptográfica e privacidade digital (`Privacy by Design`).
2. **Irreversible Zero-Knowledge Custody (No Password Recovery)**: Because OnionTalk operates without central servers, user accounts, emails, or phone numbers, **the developers cannot recover forgotten vault passwords, restore lost private keys, or reverse the 5-Strike Anti-Coercion Wipe (`DoD 5220.22-M`) or Synchronized Bilateral Burn (`🔥`)**. Users are solely responsible for safeguarding their local credentials and backups.
3. **Blind Common-Carrier Relay Safe Harbor**: Federated `.onion` v3 relay nodes act strictly as **blind, non-custodial encrypted envelope routers**. Relays possess neither the private `X25519` keys nor the post-quantum `ML-KEM-768` decapsulation keys required to inspect, filter, or modify message contents, and expose only deterministic synthetic topology coordinates (`Zero IP / Zero Cloud Provider Leak`).
4. **Lawful Use & User Responsibility**: Users assume full and exclusive legal responsibility for their use of the software in their respective jurisdictions. Using OnionTalk for unlawful activities is strictly prohibited by the project's terms of use.
5. **Non-Affiliation**: OnionTalk is an independent open-source project and is not affiliated with, endorsed by, or sponsored by *The Tor Project, Inc.*
