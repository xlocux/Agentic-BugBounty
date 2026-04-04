Sei Claude Code che gira su Kali Linux (WSL2 headless). Il tuo compito è configurare completamente il framework Agentic BugBounty per girare su questo sistema. Non chiedere conferme per operazioni standard — esegui in sequenza e riporta solo errori bloccanti.

## CONTESTO

Il framework è in ~/agentic-bugbounty (già clonato/copiato da Windows).
Struttura chiave:
- scripts/run-pipeline.js     — entry point pipeline
- .claude/settings.local.json — permessi Claude Code
- .env                        — variabili d'ambiente
- docs/GUIDE.md               — documentazione

Tre MCP server da integrare:
1. BurpSuite Pro MCP  — https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc
2. Ghidra MCP         — https://github.com/bethington/ghidra-mcp
3. Kali BugBounty MCP — https://mcpmarket.com/server/bugbounty

JAR Burp Pro si trova in ~/tools/burpsuite_pro.jar (l'utente lo copierà lì).
Ghidra sarà installato in ~/tools/ghidra/.

---

## FASE 1 — Installa dipendenze di sistema

```bash
sudo apt install -y \
  default-jdk \
  python3 python3-pip python3-venv \
  nodejs npm \
  nmap masscan \
  ffuf feroxbuster gobuster \
  sqlmap \
  nikto \
  whatweb \
  wfuzz \
  curl wget jq git \
  unzip \
  nuclei \
  amass \
  dnsrecon \
  fierce \
  wafw00f \
  ghauri \
  seclists \
  wordlists
```

Se nuclei non è disponibile via apt, installalo via Go:
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

Verifica che Java sia >= 17:
```bash
java -version
```

---

## FASE 2 — Struttura directory

```bash
mkdir -p ~/tools
mkdir -p ~/targets
mkdir -p ~/agentic-bugbounty/logs
```

---

## FASE 3 — Installa Ghidra

Cerca l'ultima release stabile su https://github.com/NationalSecurityAgency/ghidra/releases
e scarica lo zip PUBLIC. Esempio per 11.3.1:

```bash
cd ~/tools
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip
unzip ghidra_11.3.1_PUBLIC_20250219.zip
mv ghidra_11.3.1_PUBLIC ~/tools/ghidra
rm ghidra_11.3.1_PUBLIC_20250219.zip
ls ~/tools/ghidra/ghidraRun
```

Se la versione è diversa, adatta il comando wget all'URL corretto dalla pagina releases.

---

## FASE 4 — Installa ghidra-mcp

```bash
cd ~/tools
git clone https://github.com/bethington/ghidra-mcp
cd ghidra-mcp
pip3 install -r requirements.txt 2>/dev/null || pip3 install mcp 2>/dev/null || true
```

Leggi il README di ghidra-mcp e identifica:
- Comando esatto per avviare il server
- Trasporto: stdio o TCP (e porta se TCP)
- Nomi esatti dei tool MCP esposti

Riporta queste informazioni come output strutturato prima di procedere alla fase successiva.

---

## FASE 5 — Installa Kali BugBounty MCP

Cerca il package corrispondente a https://mcpmarket.com/server/bugbounty.
Prova in ordine:

```bash
npm install -g @mcpmarket/bugbounty-server 2>/dev/null || \
npm install -g mcp-bugbounty 2>/dev/null || \
pip3 install mcp-bugbounty 2>/dev/null || true
```

Se nessuno funziona, cerca il repo GitHub sorgente (cerca "mcpmarket bugbounty" su GitHub)
e clonalo in ~/tools/kali-mcp/.

Leggi il README e identifica:
- Comando di installazione corretto
- Comando di avvio
- Nomi esatti dei tool MCP esposti

Riporta queste informazioni come output strutturato prima di procedere alla fase successiva.

---

## FASE 6 — Configura Burp Pro headless

Crea il file ~/agentic-bugbounty/scripts/start-burp-headless.sh:

```bash
#!/usr/bin/env bash
BURP_JAR="${BURP_JAR:-$HOME/tools/burpsuite_pro.jar}"
BURP_API_PORT="${BURP_API_PORT:-1337}"

if [ ! -f "$BURP_JAR" ]; then
  echo "[burp] JAR non trovato: $BURP_JAR"
  echo "[burp] Copia il JAR in ~/tools/burpsuite_pro.jar"
  exit 1
fi

java -jar "$BURP_JAR" \
  --headless \
  --unpause-spider-and-scanner \
  --config-file="$HOME/.burp_config.json" \
  &

BURP_PID=$!
echo $BURP_PID > /tmp/agentic-bb-burp.pid
echo "[burp] Avviato con PID $BURP_PID, REST API su porta $BURP_API_PORT"
```

Crea il file ~/.burp_config.json:

```json
{
  "proxy": {
    "request_listeners": [
      {
        "listen_mode": "all_interfaces",
        "listen_port": 8080,
        "running": true
      }
    ]
  },
  "rest_api": {
    "enabled": true,
    "port": 1337
  }
}
```

---

## FASE 7 — Burp MCP server

Il MCP di PortSwigger (https://portswigger.net/bappstore/9952290f04ed4f628e624d0aa9dccebc)
è un BApp. Cerca se esiste una versione installabile headless o un package npm/pip.

Se non è installabile senza GUI, crea un thin MCP wrapper che parla con la Burp REST API.

Crea ~/tools/burp-mcp/ con un server MCP stdio che espone:
- burp__start_scan(url, scan_config)   — avvia scan attivo
- burp__get_issues(target_url)         — legge i finding Burp
- burp__get_sitemap(target_url)        — legge il sitemap crawlato
- burp__stop_scan(scan_id)             — ferma uno scan

Usa @modelcontextprotocol/sdk (npm). La Burp REST API base è:
  http://localhost:1337/v0.1/
  Header richiesto: X-Burp-API-Key: <key>

Endpoint principali:
  GET  /v0.1/target/scope
  POST /v0.1/scan              body: {"scope": {"include": [{"rule": "url"}]}}
  GET  /v0.1/scan/<id>
  GET  /v0.1/issue-definitions
  GET  /v0.1/target/issues     ?url=...

---

## FASE 8 — Script gestione MCP servers

Crea ~/agentic-bugbounty/scripts/start-mcp-servers.sh:

```bash
#!/usr/bin/env bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

source "$PROJECT_DIR/.env" 2>/dev/null || true

echo "[mcp] Avvio MCP servers..."

# Burp headless
if [ -f "${BURP_JAR:-$HOME/tools/burpsuite_pro.jar}" ]; then
  bash "$SCRIPT_DIR/start-burp-headless.sh"
else
  echo "[mcp] Burp JAR non trovato — skip (copia ~/tools/burpsuite_pro.jar per abilitarlo)"
fi

# Ghidra MCP — aggiorna GHIDRA_MCP_CMD dopo FASE 4
GHIDRA_MCP_DIR="${GHIDRA_MCP_DIR:-$HOME/tools/ghidra-mcp}"
if [ -d "$GHIDRA_MCP_DIR" ]; then
  cd "$GHIDRA_MCP_DIR"
  python3 server.py &
  echo $! > /tmp/agentic-bb-ghidra-mcp.pid
  echo "[mcp] Ghidra MCP avviato (PID $(cat /tmp/agentic-bb-ghidra-mcp.pid))"
else
  echo "[mcp] Ghidra MCP non trovato — skip"
fi

# Kali MCP — aggiorna dopo FASE 5
KALI_MCP_DIR="${KALI_MCP_DIR:-$HOME/tools/kali-mcp}"
if [ -d "$KALI_MCP_DIR" ]; then
  echo "[mcp] Kali MCP: aggiorna start-mcp-servers.sh con il comando corretto"
else
  echo "[mcp] Kali MCP non trovato — skip"
fi

echo "[mcp] Done."
```

Crea ~/agentic-bugbounty/scripts/stop-mcp-servers.sh:

```bash
#!/usr/bin/env bash
for pidfile in /tmp/agentic-bb-*.pid; do
  [ -f "$pidfile" ] || continue
  PID=$(cat "$pidfile")
  kill "$PID" 2>/dev/null && echo "[mcp] Stopped PID $PID ($pidfile)" || echo "[mcp] PID $PID già terminato"
  rm "$pidfile"
done
```

Rendi entrambi eseguibili:
```bash
chmod +x ~/agentic-bugbounty/scripts/start-mcp-servers.sh
chmod +x ~/agentic-bugbounty/scripts/stop-mcp-servers.sh
chmod +x ~/agentic-bugbounty/scripts/start-burp-headless.sh
```

---

## FASE 9 — Configura MCP in Claude Code

Leggi il file esistente ~/agentic-bugbounty/.claude/settings.local.json.
Mergea senza sovrascrivere i permessi esistenti, aggiungendo la sezione mcpServers
e i nuovi permessi Bash.

Il risultato finale deve essere:

```json
{
  "permissions": {
    "allow": [
      "Bash(grep -E \"\\\\.\\(js|json|md\\)$\")",
      "Bash(git rev-list:*)",
      "Bash(sort -k3 -n -r)",
      "Bash(git-filter-repo:*)",
      "Bash(./run.sh)",
      "Bash(node:*)",
      "Bash(cp:*)",
      "Bash(ccw cli:*)",
      "Bash(source .env)",
      "Bash(openssl req:*)",
      "Bash(docker compose:*)",
      "Bash(sudo apt:*)",
      "Bash(java:*)",
      "Bash(python3:*)",
      "Bash(nmap:*)",
      "Bash(ffuf:*)",
      "Bash(sqlmap:*)",
      "Bash(nuclei:*)",
      "Bash(amass:*)",
      "Bash(nikto:*)",
      "Bash(whatweb:*)",
      "Bash(feroxbuster:*)",
      "Bash(bash scripts/*:*)"
    ]
  },
  "mcpServers": {
    "burpsuite": {
      "command": "node",
      "args": ["SOSTITUISCI_CON_PATH_REALE/index.js"],
      "env": {
        "BURP_API_URL": "http://localhost:1337",
        "BURP_API_KEY": ""
      }
    },
    "ghidra": {
      "command": "python3",
      "args": ["SOSTITUISCI_CON_PATH_REALE/server.py"],
      "env": {
        "GHIDRA_HOME": "/root/tools/ghidra"
      }
    },
    "kali": {
      "command": "SOSTITUISCI_CON_COMANDO_REALE",
      "args": [],
      "env": {}
    }
  }
}
```

Sostituisci i SOSTITUISCI_CON_* con i path e comandi reali scoperti nelle fasi 4, 5, 7.

---

## FASE 10 — Aggiorna .env

Aggiungi queste righe a ~/agentic-bugbounty/.env senza sovrascrivere quelle esistenti:

```
# ── Kali tool integration ──────────────────────────────────
BURP_JAR=$HOME/tools/burpsuite_pro.jar
BURP_API_URL=http://localhost:1337
BURP_API_PORT=1337
GHIDRA_HOME=$HOME/tools/ghidra
GHIDRA_MCP_DIR=$HOME/tools/ghidra-mcp
KALI_MCP_DIR=$HOME/tools/kali-mcp
BURP_MCP_DIR=$HOME/tools/burp-mcp

# Tool binaries (auto-detected)
FFUF_BIN=$(which ffuf 2>/dev/null || echo "ffuf")
SQLMAP_BIN=$(which sqlmap 2>/dev/null || echo "sqlmap")
NUCLEI_BIN=$(which nuclei 2>/dev/null || echo "nuclei")
NMAP_BIN=$(which nmap 2>/dev/null || echo "nmap")
AMASS_BIN=$(which amass 2>/dev/null || echo "amass")
NIKTO_BIN=$(which nikto 2>/dev/null || echo "nikto")
WHATWEB_BIN=$(which whatweb 2>/dev/null || echo "whatweb")
FEROXBUSTER_BIN=$(which feroxbuster 2>/dev/null || echo "feroxbuster")
```

---

## FASE 11 — Verifica finale

Esegui questi check e riporta l'output completo:

```bash
echo "=== OS ===" && uname -a
echo "=== Java ===" && java -version 2>&1
echo "=== Node ===" && node --version
echo "=== npm ===" && npm --version
echo "=== Python ===" && python3 --version
echo "=== ffuf ===" && which ffuf 2>/dev/null || echo "MISSING"
echo "=== sqlmap ===" && which sqlmap 2>/dev/null || echo "MISSING"
echo "=== nuclei ===" && which nuclei 2>/dev/null || echo "MISSING"
echo "=== nmap ===" && which nmap 2>/dev/null || echo "MISSING"
echo "=== amass ===" && which amass 2>/dev/null || echo "MISSING"
echo "=== nikto ===" && which nikto 2>/dev/null || echo "MISSING"
echo "=== whatweb ===" && which whatweb 2>/dev/null || echo "MISSING"
echo "=== feroxbuster ===" && which feroxbuster 2>/dev/null || echo "MISSING"
echo "=== Ghidra ===" && ls ~/tools/ghidra/ghidraRun 2>/dev/null && echo "OK" || echo "MISSING"
echo "=== Ghidra MCP ===" && ls ~/tools/ghidra-mcp/ 2>/dev/null && echo "OK" || echo "MISSING"
echo "=== Burp MCP ===" && ls ~/tools/burp-mcp/ 2>/dev/null && echo "OK" || echo "MISSING"
echo "=== Kali MCP ===" && ls ~/tools/kali-mcp/ 2>/dev/null && echo "OK" || echo "MISSING"
echo "=== Burp JAR ===" && ls ~/tools/burpsuite_pro.jar 2>/dev/null && echo "OK" || echo "MISSING (copia manuale richiesta)"
echo "=== .env ===" && cat ~/agentic-bugbounty/.env
echo "=== MCP config ===" && cat ~/agentic-bugbounty/.claude/settings.local.json
```

---

## OUTPUT ATTESO

Al termine di tutte le fasi riporta un sommario strutturato:

### Installato con successo
- Lista tool/componenti installati

### Richiede azione manuale
- Burp JAR: copia ~/tools/burpsuite_pro.jar
- API key Burp: da inserire in .env dopo primo avvio
- Eventuali altri step manuali

### Tool MCP scoperti
Formato:
```
ghidra-mcp:
  avvio: <comando>
  trasporto: stdio | tcp:<porta>
  tool: <nome1>, <nome2>, ...

kali-mcp:
  avvio: <comando>
  trasporto: stdio | tcp:<porta>
  tool: <nome1>, <nome2>, ...

burp-mcp:
  avvio: <comando>
  trasporto: stdio
  tool: burp__start_scan, burp__get_issues, burp__get_sitemap, burp__stop_scan
```

### Errori bloccanti
- Lista errori che impediscono il funzionamento

---

## VINCOLI

- Non modificare nulla sotto ~/agentic-bugbounty/.claude/commands/ — i moduli researcher
  verranno aggiornati separatamente dopo aver verificato i tool MCP disponibili.
- Non modificare scripts/run-pipeline.js — l'integrazione MCP nel pipeline
  verrà aggiunta in una fase successiva.
- Se un componente non è installabile automaticamente, documenta il motivo
  e prosegui con le fasi successive.
