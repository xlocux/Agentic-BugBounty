# PROMPT 01 — Chain Synthesis
# Esegui per primo. Modifica solo i file .md dei prompt agent.
# Dopo: esegui PROMPT_02_ADAPTIVE_LOOP.md

---

Sei un ingegnere che sta evolvendo il framework Agentic-BugBounty.
Il tuo task è aggiungere la capacità di **vulnerability chaining** agli agenti
Researcher (whitebox e blackbox) e aggiornare schema e Triager di conseguenza.

Non toccare nessun file .js. Solo i file .md in `.claude/commands/shared/`.

---

## FILE DA MODIFICARE

```
.claude/commands/shared/researcher_wb.md
.claude/commands/shared/researcher_bb.md
.claude/commands/shared/core.md
.claude/commands/shared/triager_base.md
```

---

## MODIFICA A — researcher_wb.md

Trova la riga esatta:

```
## PHASE 3 — Candidate Classification
```

Inserisci il blocco seguente **immediatamente prima** di essa (lascia una riga vuota di separazione):

```markdown
---

## PHASE 2.6 — Chain Synthesis

Esegui questa fase dopo aver completato Phase 2 e Phase 2.5 e ottenuto la lista
completa dei candidati. Non saltarla anche se hai zero finding confermati —
le chain spesso elevano candidati non confermati a confermati.

**Obiettivo:** trovare coppie o triple di candidati dove la combinazione
raggiunge un impatto più alto di qualsiasi finding singolo, poi costruire
un unico PoC funzionante che dimostra l'intera escalation path.

---

### Step 1 — Costruisci la candidate matrix

Elenca tutti i candidati trovati finora. Per ciascuno scrivi una riga:

```
[ID] [vuln_class] [componente/endpoint] [cosa guadagna l'attaccante da questo da solo]
```

Esempio:

```
C-01  open_redirect     /auth/logout?next=    controlla dove atterra la vittima dopo il logout
C-02  CSRF              /api/account/email    cambia email vittima se l'attaccante controlla il referrer
C-03  info_disclosure   /debug/config         rivela hostname di servizi interni
C-04  SSRF              /api/fetch?url=       fa richieste server-side a URL controllato dall'attaccante
C-05  stored_XSS        /profile/bio          esegue JS nel browser della vittima alla visita del profilo
```

---

### Step 2 — Assegna i primitivi

Per ogni candidato identifica quale **primitivo** fornisce all'attaccante:

| Primitivo | Cosa fornisce |
|---|---|
| `redirect_control` | controllo sulla destinazione di navigate victim o server |
| `request_forgery` | far inviare al browser della vittima una richiesta autenticata |
| `js_execution` | eseguire JS arbitrario nel browser della vittima |
| `origin_escalation` | far sembrare una richiesta proveniente da un'origine fidata |
| `server_request` | far fare al server una fetch verso URL controllato dall'attaccante |
| `info_leak` | ottenere segreti, token, indirizzi interni, username |
| `desync` | confondere due componenti sui boundary di una richiesta |
| `prototype_pollution` | iniettare proprietà nel prototype globale |
| `id_control` | riferire o enumerare ID arbitrari di utenti/oggetti |
| `token_theft` | rubare session cookie, JWT, OAuth token, o CSRF token |
| `file_write` | scrivere contenuto controllato dall'attaccante nel filesystem |
| `code_exec` | eseguire comandi OS o valutare codice server-side |
| `sql_injection` | eseguire query SQL arbitrarie, leggere/modificare DB |
| `file_read` | leggere file arbitrari dal filesystem |
| `template_injection` | eseguire codice tramite template engine (SSTI) |
| `deserialization` | eseguire codice tramite deserializzazione non sicura |
| `race_condition` | sfruttare window di tempo per bypassare controlli |
| `auth_bypass` | eludere meccanismi di autenticazione |
| `xxe` | leggere file o eseguire SSRF tramite XXE |
| `ldap_injection` | manipolare query LDAP per bypass auth o estrarre dati |
| `nosql_injection` | manipolare query NoSQL per bypass auth o estrarre dati |
| `command_injection` | eseguire comandi OS arbitrari |
| `header_injection` | iniettare header HTTP (CRLF, Host, etc.) |

Un candidato può fornire più primitivi. Annota ogni candidato con i suoi.

---

### Step 3 — Matrice di escalation

Usa questa matrice per trovare le combinazioni di candidati da testare.
La matrice è organizzata per categorie. Ogni riga rappresenta una chain
realistica già documentata in contesti reali di bug bounty e penetration test.

---

#### Category 1 — Information Disclosure → Escalation

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `info_leak` | `sql_injection` | leaked DB schema/table names → SQLi mirata su tabelle sensibili (es. users, credentials) |
| `info_leak` | `id_control` | leaked user ID o email → IDOR mirato su endpoint di modifica profilo o dati sensibili |
| `info_leak` | `server_request` | leaked internal IP/hostname → SSRF mirato a servizi interni (Redis, MySQL, internal API) |
| `info_leak` | `file_read` | leaked file path da error messages → path traversal mirato a file di configurazione |
| `file_read` | `token_theft` | leggere file con JWT secret, API key, o session token → forgery di token validi |
| `file_read` | `auth_bypass` | leggere file di configurazione con credenziali hardcoded (es. .env, config.php) → bypass authentication |
| `file_read` | `code_exec` | leggere codice sorgente per identificare gadget chain per deserialization o RCE |
| `info_leak` | `race_condition` | leaked endpoint con race condition → TOCTOU su reset password o creazione account |

---

#### Category 2 — SQL Injection Chains

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `sql_injection` | `file_write` | MySQL `INTO OUTFILE` o `INTO DUMPFILE` → write webshell in document root → RCE |
| `sql_injection` | `code_exec` | MSSQL `xp_cmdshell` abilitato → RCE come utente database |
| `sql_injection` | `code_exec` | PostgreSQL `COPY` con program o `CREATE FUNCTION` con language C → RCE |
| `sql_injection` | `info_leak` | UNION-based o error-based extraction → dump completo di tabelle con PII, credenziali |
| `sql_injection` | `server_request` | MSSQL `sp_configure` + OLE automation (`sp_OACreate`) → SSRF verso interno |
| `sql_injection` | `server_request` | Oracle `utl_http` o `DBMS_LDAP` → SSRF per esfiltrazione dati out-of-band |
| `sql_injection` | `auth_bypass` | extract admin password hash → crack → authentication bypass |
| `sql_injection` | `file_read` | MySQL `LOAD_FILE()` → leggere file arbitrari dal server (config, source code) |

---

#### Category 3 — Server-Side Chains (SSRF, File Operations)

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `server_request` | `file_read` | SSRF con schema `file://` → leggere file arbitrari (/etc/passwd, application.properties) |
| `server_request` | `code_exec` | SSRF a Redis (unauth) → `CONFIG SET dir` + `dbfilename` → webshell o RCE via cron |
| `server_request` | `code_exec` | SSRF a Kubernetes API → credenziali service account → pod exec → RCE |
| `server_request` | `code_exec` | SSRF a AWS IMDS v1 → `/latest/meta-data/iam/security-credentials/` → credenziali AWS → takeover |
| `server_request` | `deserialization` | SSRF a endpoint Java con deserialization (JMX, RMI) → ysoserial → RCE |
| `file_write` | `code_exec` | write su directory web (upload, template) → webshell (PHP, JSP, ASP) → RCE |
| `file_write` | `code_exec` | write su `/etc/cron.d/` → cron job con payload → RCE |
| `file_write` | `template_injection` | write su file template (Jinja2, Freemarker, Thymeleaf) → SSTI → RCE su rendering successivo |
| `file_read` | `sql_injection` | leggere file con credenziali DB → SQL injection con privilegi elevati (DBA, root) |
| `server_request` | `info_leak` | SSRF a cloud metadata (AWS, GCP, Azure) → credenziali e token di servizio |
| `server_request` | `file_write` | SSRF a internal API con file upload → write su filesystem |

---

#### Category 4 — Client-Side Chains (XSS, CSRF, Redirect)

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `js_execution` | `request_forgery` | XSS → CSRF (bypass SameSite via same-origin fetch con cookie già presenti) |
| `js_execution` | `token_theft` | XSS → exfiltrare session cookie via `document.cookie` o localStorage → ATO |
| `js_execution` | `token_theft` | XSS → rubare JWT da localStorage o sessionStorage → ATO |
| `js_execution` | `id_control` | XSS → usare contesto autenticato vittima per cambiare ID in endpoint vulnerabili a IDOR |
| `js_execution` | `origin_escalation` | XSS → modificare CORS settings via fetch con `credentials: include` → rubare risposte |
| `redirect_control` | `token_theft` | open redirect su OAuth callback → intercettare authorization code (OAuth 2.0) |
| `redirect_control` | `token_theft` | open redirect su SAML endpoint → intercettare SAML response con assertion |
| `redirect_control` | `js_execution` | open redirect a `javascript:alert(1)` in sink che eseguono URL (es. window.location) → XSS |
| `header_injection` | `request_forgery` | CRLF injection in header → response splitting → XSS o request poisoning |
| `header_injection` | `js_execution` | CRLF injection → inject script tag via Content-Type manipulation → XSS |
| `origin_escalation` | `request_forgery` | CORS misconfiguration (`Access-Control-Allow-Origin: *` con credentials) → CSRF da origine arbitraria |
| `origin_escalation` | `token_theft` | CORS misconfiguration → leggere risposte con token tramite JavaScript cross-origin |

---

#### Category 5 — Authentication & Authorization Bypass

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `auth_bypass` | `id_control` | authentication bypass su endpoint (es. admin=true param) → accedere a endpoint IDOR protetti |
| `auth_bypass` | `request_forgery` | bypass auth su endpoint state-changing → CSRF senza bisogno di token |
| `race_condition` | `id_control` | TOCTOU su limit rate o quota → escalation di privilegi (es. gift card multiple redemption) |
| `race_condition` | `auth_bypass` | race condition su registration/login → account takeover via duplicate registration |
| `auth_bypass` | `sql_injection` | authentication bypass tramite SQL injection (es. `' OR '1'='1`) → accesso come admin |
| `race_condition` | `file_write` | race condition su file upload → overwrite file critici |

---

#### Category 6 — Injection Chains (Template, LDAP, NoSQL, Command)

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `template_injection` | `code_exec` | SSTI in Jinja2 → `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}` → RCE |
| `template_injection` | `code_exec` | SSTI in Freemarker → evaluation chain fino a `freemarker.template.utility.Execute` → RCE |
| `template_injection` | `file_read` | SSTI → leggere file template o configurazione tramite file system access |
| `ldap_injection` | `auth_bypass` | LDAP injection su login (`*` o `uid=*)(|(uid=*)`) → bypass authentication |
| `ldap_injection` | `info_leak` | LDAP injection → extract directory structure, user DN, gruppi |
| `nosql_injection` | `auth_bypass` | MongoDB injection su login (`$ne` o `$gt`) → bypass authentication |
| `nosql_injection` | `id_control` | NoSQL injection → enumerare o modificare documenti di altri utenti tramite operatori |
| `command_injection` | `code_exec` | command injection in input → RCE diretta (system, exec, eval) |
| `command_injection` | `file_read` | command injection con `cat` o `type` → leggere file arbitrari |
| `command_injection` | `server_request` | command injection con `curl` o `wget` → SSRF out-of-band per exfiltrazione |

---

#### Category 7 — Deserialization & Protocol Chains

| A (primitivo) | B (primitivo) | Chain result |
|---|---|---|
| `deserialization` | `code_exec` | Java deserialization con ysoserial → RCE via gadget chain (CommonsCollections, Groovy, etc.) |
| `deserialization` | `code_exec` | PHP deserialization con gadget chain (Laravel, Symfony, Monolog) → RCE via `__destruct` |
| `deserialization` | `code_exec` | Python pickle → RCE via `__reduce__` o `__setstate__` |
| `deserialization` | `file_write` | deserialization gadget chain → write file arbitrari (webshell, cron job) |
| `xxe` | `file_read` | XXE classic → leggere file arbitrari (file://) |
| `xxe` | `server_request` | XXE con external entity → SSRF verso interno (HTTP request) |
| `xxe` | `server_request` | XXE con parameter entities → out-of-band exfiltration via HTTP/DNS |
| `desync` | `request_forgery` | HTTP request smuggling (CL.TE o TE.CL) → request queue poisoning → ATO |
| `desync` | `js_execution` | HTTP response queue poisoning → inject response → DOM XSS in vittima successiva |
| `desync` | `token_theft` | HTTP smuggling → capture Authorization header di richiesta successiva |

---

#### Category 8 — Composite Chains (3 step)

Queste chain richiedono tre vulnerabilità distinte in sequenza. Sono state
documentate in bug bounty reali (HackerOne, Bugcrowd) e penetration test.

| Step 1 | Step 2 | Step 3 | Chain result |
|---|---|---|---|
| `info_leak` (leaked internal IP) | `server_request` (SSRF) | `code_exec` | leaked IP → SSRF a Redis unauth → RCE via Redis Lua script |
| `file_read` (leaked credenziali DB) | `info_leak` (schema DB) | `sql_injection` | file con credenziali → info leak su schema → SQLi avanzata con UNION |
| `redirect_control` | `request_forgery` | `token_theft` | open redirect su OAuth → CSRF cambio email → password reset → ATO |
| `js_execution` | `origin_escalation` | `token_theft` | XSS → CORS bypass via fetch → steal admin token |
| `server_request` | `file_write` | `code_exec` | SSRF a internal upload API → write su directory web → webshell |
| `info_leak` | `id_control` | `request_forgery` | leaked user ID pattern → IDOR su endpoint cambio email → CSRF su conferma |
| `auth_bypass` | `race_condition` | `id_control` | bypass auth su reset password → race condition su token generation → ATO |
| `sql_injection` | `file_write` | `code_exec` | SQLi UNION → write webshell via INTO OUTFILE → RCE |
| `file_read` | `template_injection` | `code_exec` | leggere template file → identificare SSTI vector → RCE |
| `deserialization` | `server_request` | `info_leak` | deserialization → SSRF via gadget chain → exfiltrare dati interni |

---

### Step 4 — PoC della chain (uno per coppia o tripla valida)

Per ogni match identificato in Step 3:

**4.1** Formula l'ipotesi in una frase:
  "Se uso C-01 (redirect_control) per soddisfare il check referrer in C-02
   (request_forgery), la chain raggiunge account email takeover senza
   interazione della vittima oltre al click su un link."

**4.2** Costruisci un PoC minimale e self-contained che esercita la chain
  end-to-end. Il PoC non deve richiedere passi manuali oltre il trigger iniziale.

**4.3** Esegui il PoC. Osserva il risultato.

**4.4** Se la chain ha successo:
  - Assegna un nuovo report_id: usa il prefix del candidato con ID più alto + suffisso "C"
    Es: se la chain usa WEB-003 e WEB-007, il nuovo ID è WEB-007C
  - Imposta la severity al livello massimo raggiunto dalla chain (non la media dei pezzi)
  - Imposta vulnerability_class alla classe dominante che abilita la chain
  - Popola `chain_meta` (vedi aggiornamento schema in core.md)
  - I candidati individuali assorbiti nella chain vanno in unconfirmed_candidates
    con reason_not_confirmed = "absorbed into chain [ID]"

**4.5** Se la chain fallisce (precondizione non soddisfacibile):
  - Annota il motivo nelle tue note di analisi
  - Mantieni entrambi i candidati come finding individuali alla loro severity originale

---

### Step 5 — Regole CVSS per chain

Quando scoring un finding a catena, usa il CVSS dell'**ultimo step** della chain
(l'impatto consegnato alla vittima o al sistema), ma aggiusta questi metrici:

- **AC (Attack Complexity):** alza di un livello per ogni step intermedio non banale
  - 0–1 step intermedi con interazione utente: AC:L
  - 2+ step intermedi O 1 step che richiede timing specifico: AC:H
- **PR (Privileges Required):** usa il valore del PRIMO step della chain
  (riflette la precondizione reale per l'attaccante)
- **UI (User Interaction):** Required se QUALSIASI step della chain richiede
  interazione della vittima
- **Scope:** Changed se la chain attraversa un security boundary (es. da client
  a server, dal contesto di un utente a quello di un altro)

Documenta ogni scelta metrica in researcher_notes così il Triager può verificarla.

---

### Output di Phase 2.6

Aggiungi i chain finding all'array findings principale con
confirmation_status = "confirmed" (solo se il PoC ha avuto successo end-to-end).

Aggiungi un chain_synthesis_summary alle tue note di analisi:

```
CHAIN SYNTHESIS SUMMARY
Candidati valutati:  [N]
Chain tentate:       [N]
Chain confermate:    [N]
Chain fallite:       [N] (motivi: ...)
Candidati assorbiti: [IDs]
```

---
```

---

## MODIFICA B — researcher_bb.md

Trova la riga esatta:

```
## PHASE 3 — Active Testing
```

Inserisci il blocco seguente **immediatamente prima** di essa (lascia una riga vuota):

```markdown
---

## PHASE 2.5 — Chain Synthesis (Black-Box)

Il chain synthesis blackbox gira dopo Phase 2 (Passive Analysis) e prima
del testing attivo. Non puoi leggere il codice sorgente, ma puoi osservare
primitivi comportamentali dall'esterno e ragionare su come si combinano.

**Differenza chiave rispetto al whitebox:** scopri i primitivi tramite probing,
non lettura del codice. Testa ogni ipotesi di primitivo con una probe leggera
prima di committarti a un PoC completo della chain.

### Step 1 — Lista le osservazioni comportamentali da Phase 2

Per ogni anomalia o comportamento interessante notato in Phase 2, scrivi:

```
[OBS-N] [cosa hai osservato] [quale primitivo suggerisce]
```

Esempio:

```
OBS-01  /logout?next= accetta URL arbitrari senza validazione        → redirect_control
OBS-02  /api/user/profile restituisce oggetto completo inclusa email → info_leak
OBS-03  POST /api/settings non ha CSRF token in request o response   → request_forgery candidato
OBS-04  CORS header: Access-Control-Allow-Origin: * con credentials  → origin_escalation
OBS-05  /api/webhooks/{id}/url — ID è intero sequenziale             → id_control
```

### Step 2 — Applica la primitive matrix

Usa la stessa matrice di researcher_wb.md Phase 2.6 Step 3.
Associa le tue osservazioni OBS-N ai candidati chain.

### Step 3 — Probe leggere per confermare i primitivi

Prima di costruire un PoC completo della chain, conferma ogni primitivo
con una probe minimale:

- **redirect_control:** il redirect viene effettivamente eseguito? Funziona cross-origin?
- **request_forgery:** la richiesta state-changing ha successo senza CSRF token?
  Test: invia la richiesta da un'origine diversa via curl o un form HTML semplice.
- **origin_escalation:** il server echo `Access-Control-Allow-Origin` per origini
  arbitrarie? Funziona con `withCredentials: true`?
- **info_leak:** il dato trapelato (hostname, token, ID) appare consistentemente?
  È specifico dell'utente o globale?
- **id_control:** puoi accedere alla risorsa di un altro utente cambiando l'ID?
  Test con due account che controlli.
- **sql_injection:** errori SQL visibili? Time-based response? Boolean-based?
  Test con payload classici (`'`, `"`, `1' AND '1'='1`).
- **server_request:** l'endpoint accetta URL e fa richieste? Test con collaborator.
- **file_read:** parametri path? Test con `../../etc/passwd` o `/etc/passwd`.
- **template_injection:** il server interpreta `{{7*7}}`? La risposta contiene `49`?
- **command_injection:** test con `;sleep 5`, `|sleep 5`, `$(sleep 5)`.

Se una probe di primitivo fallisce: rimuovilo dai candidati chain. Non assumere.

### Step 4 — Chain PoC

Segui le stesse regole di PoC, scoring e output di researcher_wb.md Phase 2.6
Steps 4–5. Vincolo blackbox: il PoC deve essere completamente esterno
(nessun riferimento al codice sorgente).

---
```

---

## MODIFICA C — core.md (schema REPORT_BUNDLE)

### Parte C1 — Campo nel JSON schema

Trova questa riga esatta nel JSON schema dentro il blocco ` ```json `:

```
      "attachments": []
```

Sostituiscila con:

```json
      "attachments": [],
      "chain_meta": null
```

### Parte C2 — Documentazione del campo

Trova il blocco che chiude il JSON schema (la riga con solo ` ``` `
che chiude il blocco json del REPORT_BUNDLE). Immediatamente dopo
quella riga di chiusura, prima del separatore `---`, inserisci:

```markdown
### chain_meta — solo per finding a catena

Quando un finding è il risultato della combinazione di due o più vulnerabilità,
popola `chain_meta` con questa struttura invece di lasciarlo null:

```json
"chain_meta": {
  "is_chain": true,
  "chain_steps": [
    {
      "step": 1,
      "report_id_source": "WEB-003",
      "vuln_class": "open_redirect",
      "primitive_provided": "redirect_control",
      "component": "/auth/logout?next=",
      "precondition": "la vittima clicca il link dell'attaccante"
    },
    {
      "step": 2,
      "report_id_source": "WEB-007",
      "vuln_class": "CSRF",
      "primitive_provided": "request_forgery",
      "component": "POST /api/account/email",
      "precondition": "l'attaccante controlla la destinazione del redirect"
    }
  ],
  "primitives_used": ["redirect_control", "request_forgery"],
  "absorbed_finding_ids": ["WEB-003", "WEB-007"],
  "chain_severity_rationale": "open_redirect da solo = Low; CSRF da solo = Medium; la chain raggiunge account email takeover senza privilegi aggiuntivi = High"
}
```

Per chain a 3 step, estendi `chain_steps` con un terzo oggetto:

```json
{
  "step": 3,
  "report_id_source": "WEB-012",
  "vuln_class": "RCE_via_template_injection",
  "primitive_provided": "code_exec",
  "component": "/admin/template/edit",
  "precondition": "l'attaccante ha ottenuto accesso admin via chain step 1-2"
}
```

Regole:
- `chain_steps` deve essere in ordine di esecuzione (step 1 = prima azione dell'attaccante)
- `report_id_source` referenzia il finding candidato individuale originale
- `absorbed_finding_ids` elenca tutti i finding collassati in questo chain report
- `chain_severity_rationale` deve giustificare la severity della chain vs. i pezzi
- Se `is_chain = true`, il campo `attack_flow_diagram` è **obbligatorio** (non opzionale)
```

---

## MODIFICA D — triager_base.md

### Parte D1 — Blocco 3.1.5 (validazione chain)

Trova questo blocco esatto in CHECK 3:

```
    If THEORETICAL → downgrade severity by 2 levels minimum
```

Immediatamente dopo quella riga, inserisci:

```markdown

3.1.5 Gestione dei chain finding:
    Se il finding ha chain_meta.is_chain = true:

    a) Verifica ogni step in chain_meta.chain_steps indipendentemente:
       - Il componente referenziato in ogni step esiste effettivamente?
       - Il primitive_provided è coerente con la vulnerabilità a quello step?
       - La precondizione dello step N è soddisfacibile dato l'output dello step N-1?

    b) Verifica il PoC della chain end-to-end:
       - Il PoC deve dimostrare l'impatto FINALE, non solo lo step 1
       - PoC parziale (dimostra solo step 1) → NEEDS_MORE_INFO, non TRIAGED
       - Se uno step intermedio fallisce → la chain collassa a finding individuali
         Rivaluta ogni absorbed_finding_id indipendentemente alla sua severity originale

    c) Validazione severity della chain:
       - La severity della chain deve essere maggiore di QUALSIASI step singolo
       - Se la severity della chain è uguale allo step più alto → downgrade a quella severity
         (la chain non aggiunge valore di escalation)
       - Se la severity è giustificata dall'impatto finale → accetta il CVSS del researcher
         ma verifica il metrico AC usando le chain CVSS scoring rules in researcher_wb.md Phase 2.6 Step 5

    d) Credit policy per chain novel:
       - Un PoC chain funzionante tra due finding Low/Medium è ALTO valore
       - NON fare downgrade di un chain finding perché i pezzi singoli sembrano di bassa severity
       - NON richiedere al researcher di sottomettere i finding individuali separatamente
       - Il chain report sostituisce completamente i finding individuali
```

### Parte D2 — Campo nel TRIAGE_RESULT schema

Trova questa riga esatta nel JSON schema di TRIAGE_RESULT:

```
      "key_discrepancies": [],
```

Sostituiscila con:

```json
      "key_discrepancies": [],
      "chain_validation": null,
```

### Parte D3 — Documentazione chain_validation

Trova la riga di chiusura ` ``` ` del JSON schema di TRIAGE_RESULT.
Immediatamente dopo, inserisci:

```markdown
### chain_validation — solo quando il finding ha chain_meta.is_chain = true

```json
"chain_validation": {
  "steps_verified": [
    {
      "step": 1,
      "component_exists": true,
      "primitive_confirmed": true,
      "precondition_satisfiable": true,
      "notes": ""
    }
  ],
  "chain_poc_verified": true,
  "chain_collapses_to": null,
  "severity_escalation_justified": true,
  "chain_verdict": "CHAIN_VALID | CHAIN_PARTIAL | CHAIN_COLLAPSED"
}
```

`chain_collapses_to`: se chain_verdict = CHAIN_COLLAPSED, elenca gli ID dei
finding individuali da rivalutare con la loro severity standalone.

Verdetti:
- `CHAIN_VALID` → PoC chain completo verificato, severity accettata
- `CHAIN_PARTIAL` → step 1 confermato ma chain completa non dimostrata → NEEDS_MORE_INFO
- `CHAIN_COLLAPSED` → almeno uno step intermedio è fallito → rivaluta le parti individualmente
```

### Parte D4 — Validazione primitivi specializzati

Trova la riga che chiude la sezione CHECK 3 (dopo il blocco 3.1.5).
Immediatamente dopo, inserisci:

```markdown

3.1.6 Validazione primitivi specializzati per chain:
    Per chain che coinvolgono primitivi complessi, verifica con questi criteri:

    sql_injection:
      - Il PoC dimostra estrazione dati? O solo error-based inference?
      - La chain richiede out-of-band? (DNS/HTTP exfiltration confermata con collaborator)
      - Per chain con INTO OUTFILE: il file è effettivamente scritto? Path accessibile via web?

    file_read:
      - Il path è controllabile dall'attaccante? Ci sono filtri (WAF, allowlist)?
      - Il PoC legge un file di prova (es. /etc/passwd o WEB-INF/web.xml)
      - Per chain con file_read → code_exec: il codice letto contiene gadget utilizzabili?

    template_injection:
      - Il contesto è template engine (Jinja2, Freemarker, Twig, Thymeleaf, ERB)?
      - Il PoC dimostra execution (es. {{config}} in Flask, ${7*7} in Freemarker)
      - La chain verso RCE richiede gadget specifici? Sono presenti nel contesto?

    deserialization:
      - È confermato il gadget chain? (ysoserial, PHPGGC, etc.)
      - Il PoC dimostra execution (ping, sleep, DNS callback) o solo crash/error?
      - Per chain con SSRF: il gadget chain supporta richieste HTTP verso interno?

    race_condition:
      - Il PoC dimostra la window di tempo con richieste concorrenti (es. 10–50 thread)?
      - Il race produce uno stato inconsistente verificabile (es. doppio redeem)?
      - Il PoC include timing measurement per dimostrare la condizione?

    xxe:
      - Il PoC utilizza external entity? Funziona con file://? Funziona con HTTP?
      - Per chain con SSRF: l'endpoint target risponde? C'è out-of-band detection?

    command_injection:
      - Il PoC dimostra execution con comando innocuo (sleep, ping, DNS lookup)?
      - La chain verso RCE è diretta o richiede bypass (WAF, character restrictions)?
```

---

## VERIFICA FINALE

Dopo aver applicato tutte le modifiche, esegui:

```bash
grep -n "chain_meta\|Phase 2.6\|Phase 2.5\|chain_validation\|primitives_used\|CHAIN_VALID\|sql_injection\|template_injection\|deserialization\|race_condition" \
  .claude/commands/shared/researcher_wb.md \
  .claude/commands/shared/researcher_bb.md \
  .claude/commands/shared/core.md \
  .claude/commands/shared/triager_base.md
```

Risultato atteso: almeno un hit per file, con le nuove righe di matrice incluse.
Nessun altro file deve essere stato modificato.
