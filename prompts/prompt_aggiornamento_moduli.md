# Prompt universale — Aggiornamento moduli Agentic-BugBounty

Usa questo prompt con qualsiasi AI (Claude, GPT-4, Gemini, ecc.) per aggiornare
i moduli di vulnerabilità del framework Agentic-BugBounty in modo coerente con
la struttura esistente.

---

## PROMPT DA COPIARE

```
Sei un esperto di sicurezza offensiva e prompt engineering per agenti AI.
Stai lavorando al framework Agentic-BugBounty, un sistema di bug bounty
automatizzato basato su Claude Code.

Il framework usa moduli markdown (.md) come prompt document per agenti AI.
Ogni modulo ha questa struttura fissa:

1. THREAT MODEL — descrizione dell'attack surface specifica
2. VULNERABILITY CLASSES — lista prioritizzata con CWE
3. WHITEBOX STATIC ANALYSIS — grep patterns per linguaggio
4. BLACKBOX TESTING PLAYBOOK — step numerati con curl/python/bash
5. TOOLS — tool specifici per questa vulnerability class

Regole di stile del framework:
- Ogni step del playbook ha un titolo (### Step N — nome)
- I payload sono sempre in blocchi di codice con linguaggio specificato
- Ogni test ha un commento "Confirm:" che dice come verificare il risultato
- Ogni test ha un commento "Report only if:" con le condizioni minime per segnalarlo
- I grep pattern includono sempre un commento su cosa verificare dopo il match
- I nuovi contenuti non duplicano ciò che esiste già — si integrano o ampliano

---

MODULO ESISTENTE DA AGGIORNARE:
[INCOLLA QUI IL CONTENUTO COMPLETO DEL FILE .md DA AGGIORNARE]

---

NUOVE INFORMAZIONI DA INTEGRARE:
[INCOLLA QUI LE NUOVE TECNICHE, RICERCHE, O PATTERN DA AGGIUNGERE]

---

IL TUO COMPITO:

1. Analizza le nuove informazioni e identifica dove si inseriscono nel modulo
   (nuovo step del playbook, estensione di uno step esistente, nuovo grep pattern,
   nuovo tool, aggiornamento del threat model, ecc.)

2. Produci SOLO le sezioni modificate o aggiunte, non riscrivere l'intero file.
   Usa questo formato:

   ### MODIFICA: [nome della sezione o dello step]
   **Tipo:** [aggiunta | estensione | sostituzione | nuovo step]
   **Posizione:** [dopo Step N | in cima a WHITEBOX GREP | fine del file | ecc.]
   **Motivazione:** [una riga — perché questa modifica migliora il modulo]

   [contenuto markdown da inserire]

3. Se la nuova informazione introduce un bypass di una difesa già documentata,
   aggiungi esplicitamente una riga "Bypass note:" nell'area rilevante del modulo
   che indica quale mitigazione esistente viene aggirata.

4. Se la nuova informazione è già coperta dal modulo (anche parzialmente),
   indica solo cosa manca e proponi un'estensione minima invece di riscrivere.

5. Non aggiungere tool che non siano reali e verificabili (no tool inventati).

Output finale: blocchi markdown pronti per essere copiati nel file .md,
senza spiegazioni aggiuntive fuori dai blocchi stessi.
```

---

## COME USARLO — ESEMPIO CONCRETO

### Scenario
Vuoi aggiungere al modulo `graphql.md` le tecniche di batching per
rate limit bypass (array batching + alias batching).

### Passo 1 — Prepara il prompt
Copia il testo sopra e sostituisci i placeholder:

```
MODULO ESISTENTE DA AGGIORNARE:
[incolla il contenuto di .claude/commands/asset/webapp/vuln/graphql.md]

NUOVE INFORMAZIONI DA INTEGRARE:
Most GraphQL endpoints accept arrays of operations in a single HTTP request.
Instead of sending one login request at a time (rate limited after 5 attempts),
you send 1000 login mutations in one request. The server processes all of them.
Rate limiting usually counts HTTP requests, not operations within a request.

Payload esempio:
[
  {"query": "mutation { login(user:\"admin\", pass:\"password1\") { token }}"},
  {"query": "mutation { login(user:\"admin\", pass:\"password2\") { token }}"},
  ...
]

Also check for alias-based batching — same attack with named aliases:
{ a1: login(pass:"pass1") a2: login(pass:"pass2") ... }
Some devs patch array batching but forget aliases. Easy bypass.
```

### Passo 2 — Interpreta l'output dell'AI
L'AI produrrà blocchi del tipo:

```
### MODIFICA: Step 2b — Batch query brute force
**Tipo:** estensione
**Posizione:** dopo lo Step 2 esistente (alias batching)
**Motivazione:** il modulo documenta alias batching ma manca un payload
realistico per il caso d'uso login brute-force con array syntax e una
nota esplicita sul bypass dei rate limiter a livello HTTP.

[markdown da inserire]
```

### Passo 3 — Applica manualmente (o con un secondo prompt)
Copia il blocco generato nel punto indicato nel file .md originale.

Per applicarlo in automatico puoi usare questo secondo prompt:

```
Hai il file originale e le modifiche proposte.
Produci il file completo aggiornato, integrando le modifiche nei punti indicati,
senza alterare nessun'altra sezione. Output: solo il markdown del file finale.
```

---

## ADATTAMENTI PER ALTRI CASI D'USO

### Aggiungere un nuovo modulo da zero
Sostituisci la sezione "MODULO ESISTENTE" con:
```
STRUTTURA DA CREARE: nuovo modulo per [nome vulnerability class]
Asset type: [webapp | mobileapp | browserext | executable]
Report ID prefix: [WEB | MOB | EXT | EXE]-[SIGLA]
```

### Aggiornare i grep pattern per un nuovo framework/linguaggio
Aggiungi alle nuove informazioni:
```
Framework: [nome]
Linguaggio: [linguaggio]
Sink pericolosi: [lista funzioni]
Pattern di mitigazione: [cosa cercare per escludere false positive]
```

### Aggiungere un bypass module in shared/bypass/
Specifica nella sezione "MODULO ESISTENTE":
```
File target: .claude/commands/shared/bypass/[nome].md
Tipo: bypass module (non playbook standalone)
```
I bypass module hanno struttura diversa: solo tecniche di evasione,
nessun threat model, nessun tool section.

---

## NOTE PER L'USO

- Testa sempre il modulo aggiornato su un target reale (anche una lab VM)
  prima di usarlo in produzione.
- Se l'AI produce step con "Confirm:" assente, aggiungilo manualmente —
  è il guardrail principale contro i finding teorici.
- Per moduli molto lunghi (>300 righe), incolla solo la sezione rilevante
  invece del file completo per non eccedere il context window dei modelli free.
- Il prompt funziona meglio con modelli che seguono istruzioni strutturate
  (Claude, GPT-4o, Gemini 1.5 Pro). Con modelli free su OpenRouter i risultati
  sono più variabili — verifica sempre l'output prima di applicarlo.
```
