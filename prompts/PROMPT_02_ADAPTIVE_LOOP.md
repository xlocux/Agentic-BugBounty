# PROMPT 02 — Adaptive Recon Loop
# Esegui dopo PROMPT_01. Modifica solo scripts/run-pipeline.js.
# Dopo: esegui PROMPT_03_MULTI_AGENT.md

---

Sei un ingegnere che sta evolvendo il framework Agentic-BugBounty.
Il tuo task è aggiungere un **adaptive recon loop** al pipeline: dopo ogni
fase del Researcher, il pipeline rileva se sono emersi nuovi signal
(nuovi endpoint, stack tecnologici, o asset inattesi) e, se sì, aggiorna
l'intelligence in `intelligence/recon_updates.json` e la inietta nel
prompt della fase successiva.

Modifica **solo** `scripts/run-pipeline.js`.
Non toccare nessun file .md né altri file .js.

---

## CONTESTO ARCHITETTURALE

Il pipeline attuale in `main()` esegue questo flusso lineare:

```
syncIntel → [researcher loop per asset] → dualResearcher → triage → reports
```

Il `runResearcherPhase()` costruisce un `extraText` che viene iniettato nel
prompt di Claude Code. Questo `extraText` contiene già il risultato del
hybrid recon (Phase 0+1 via free LLM).

L'adaptive loop che aggiungerai funziona così:

```
runResearcherPhase(asset_N)
    ↓
detectReconSignals(bundlePath, prevSignals)   ← NUOVO
    ↓ (se nuovi signal trovati)
updateReconIntelligence(context, newSignals)  ← NUOVO
    ↓
runResearcherPhase(asset_N+1, extraText += reconUpdateHint)
```

Anche all'interno di un singolo asset (non solo tra asset multipli),
dopo la prima researcher pass e prima del dual researcher pass,
il loop verifica se il bundle contiene signal che meritano una
seconda researcher pass con focus aggiornato.

---

## MODIFICHE DA IMPLEMENTARE

### 1. Aggiungi la funzione `detectReconSignals` 

Inserisci questa funzione subito dopo la funzione `mergeResearcherFindings`
(circa riga 1060 del file originale):

```javascript
/**
 * Analizza il report_bundle corrente e il bundle precedente per rilevare
 * nuovi signal di recon emersi durante la researcher pass.
 *
 * Restituisce un oggetto { hasNew: boolean, signals: string[] } dove
 * signals è una lista di osservazioni human-readable da iniettare nel prompt.
 *
 * "Signal" = qualsiasi informazione che allarga la superficie d'attacco
 * rispetto a quanto noto prima della pass: nuovi endpoint, stack, domini,
 * componenti interni, credenziali parziali, o tecnologie inattese.
 */
function detectReconSignals(bundlePath, prevSignalSet) {
  if (!fs.existsSync(bundlePath)) return { hasNew: false, signals: [] };

  let bundle;
  try {
    bundle = readJson(bundlePath);
  } catch {
    return { hasNew: false, signals: [] };
  }

  const findings = bundle.findings || [];
  const candidates = bundle.unconfirmed_candidates || [];
  const all = [...findings, ...candidates];

  const signals = [];

  for (const item of all) {
    // Endpoint / componenti non visti prima
    const comp = (item.affected_component || "").trim();
    if (comp && !prevSignalSet.has(`comp:${comp}`)) {
      prevSignalSet.add(`comp:${comp}`);
      signals.push(`Nuovo componente scoperto: ${comp}`);
    }

    // Stack tecnologici menzionati nelle note del researcher
    const notes = (item.researcher_notes || "") + (item.summary || "");
    const stackMatches = notes.match(
      /\b(Laravel|Spring|Django|Rails|Next\.js|Nuxt|Express|FastAPI|Gin|Echo|Fiber|Symfony|CodeIgniter|Struts|Quarkus|Micronaut)\b/gi
    );
    if (stackMatches) {
      for (const tech of stackMatches) {
        const key = `tech:${tech.toLowerCase()}`;
        if (!prevSignalSet.has(key)) {
          prevSignalSet.add(key);
          signals.push(`Tecnologia identificata: ${tech}`);
        }
      }
    }

    // Domini / hostname interni menzionati
    const hostMatches = notes.match(/\b([a-z0-9-]+\.(internal|local|corp|intranet|svc|cluster\.local))\b/gi);
    if (hostMatches) {
      for (const host of hostMatches) {
        const key = `host:${host.toLowerCase()}`;
        if (!prevSignalSet.has(key)) {
          prevSignalSet.add(key);
          signals.push(`Hostname interno scoperto: ${host}`);
        }
      }
    }

    // Vulnerability class ad alto valore trovata — potrebbe aprire nuove superfici
    const highValueClasses = ["ssrf", "xxe", "deserialization", "rce", "ssti", "prototype_pollution"];
    const vulnClass = (item.vulnerability_class || "").toLowerCase();
    if (highValueClasses.some((c) => vulnClass.includes(c))) {
      const key = `highval:${vulnClass}`;
      if (!prevSignalSet.has(key)) {
        prevSignalSet.add(key);
        signals.push(`Finding ad alto valore trovato (${item.vulnerability_class}) — verifica superfici correlate`);
      }
    }
  }

  return { hasNew: signals.length > 0, signals };
}
```

---

### 2. Aggiungi la funzione `buildAdaptiveReconHint`

Inserisci questa funzione immediatamente dopo `detectReconSignals`:

```javascript
/**
 * Costruisce il testo da iniettare nel prompt del Researcher
 * basandosi sui nuovi signal di recon rilevati.
 */
function buildAdaptiveReconHint(signals, reconUpdatePath) {
  if (!signals || signals.length === 0) return "";

  // Persisti i signal su disco per tracciabilità
  let existing = [];
  try {
    if (fs.existsSync(reconUpdatePath)) {
      existing = readJson(reconUpdatePath) || [];
    }
  } catch { /* ignora errori di lettura */ }

  const timestamp = new Date().toISOString();
  const newEntries = signals.map((s) => ({ signal: s, detected_at: timestamp }));
  try {
    fs.writeFileSync(reconUpdatePath, JSON.stringify([...existing, ...newEntries], null, 2), "utf8");
  } catch { /* non bloccare il pipeline se la scrittura fallisce */ }

  const signalList = signals.map((s) => `  • ${s}`).join("\n");

  return `

ADAPTIVE RECON UPDATE — nuovi signal rilevati dalla pass precedente:
${signalList}

Istruzioni:
  1. Considera questi signal come nuovi punti di partenza per l'analisi.
  2. Per ogni componente/tecnologia/hostname nuovo: verifica se apre superfici
     di attacco non coperte nei finding precedenti.
  3. Per i finding ad alto valore: cerca varianti, bypass, e vettori secondari
     correlati (es. se trovato SSRF → cerca redirect chain, DNS rebinding, etc.)
  4. Non duplicare finding già nel bundle. Aggiungi solo nuove scoperte.`;
}
```

---

### 3. Modifica `runResearcherPhase`

Trova la funzione `runResearcherPhase` e aggiungi un parametro opzionale
`signalSet` e la logica di signal detection. La firma attuale è:

```javascript
async function runResearcherPhase(cli, assetContext, args, bundlePath, isAdditional, runLog, resumeHint = "") {
```

Sostituisci l'intera funzione con:

```javascript
async function runResearcherPhase(cli, assetContext, args, bundlePath, isAdditional, runLog, resumeHint = "", signalSet = null) {
  let extraText = isAdditional
    ? `\n\nIMPORTANT: A report_bundle.json already exists from a previous asset pass. APPEND your new findings to it — do NOT remove or overwrite existing entries.`
    : "";
  if (resumeHint) extraText += resumeHint;
  logEvent(runLog, `Starting researcher phase asset=${assetContext.asset} source=${assetContext.target}`);

  // Inietta adaptive recon hint se disponibile
  if (signalSet) {
    const reconUpdatePath = assetContext.intelligenceDir
      ? path.join(assetContext.intelligenceDir, "recon_updates.json")
      : null;

    // Snapshot del bundle prima della pass per rilevare nuovi signal dopo
    const bundleSnapshotBefore = fs.existsSync(bundlePath)
      ? (readJson(bundlePath).findings || []).length
      : 0;

    // Costruisci hint dai signal già accumulati (per questa pass)
    const hint = buildAdaptiveReconHint([...signalSet].map((s) => s.replace(/^(comp|tech|host|highval):/, "")), reconUpdatePath);
    if (hint) {
      extraText += hint;
      logEvent(runLog, `Adaptive recon hint injected (${signalSet.size} signals)`);
    }

    // Salva il conteggio pre-pass per il rilevamento post-pass
    assetContext._bundleCountBefore = bundleSnapshotBefore;
  }

  // Run Phase 0+1 via free LLM to save Claude tokens
  try {
    logEvent(runLog, "Running hybrid recon (Phase 0+1) via free LLM...");
    const reconContext = await runHybridRecon(assetContext, path.resolve(__dirname, ".."));
    const reconText = formatReconContextForPrompt(reconContext);
    if (reconText) {
      extraText += reconText;
      logEvent(runLog, "Hybrid recon injected into researcher prompt", "ok");
    } else {
      logEvent(runLog, "Hybrid recon skipped — Claude will handle Phase 0+1", "warn");
    }
  } catch (e) {
    logEvent(runLog, `Hybrid recon error: ${e.message} — Claude handles Phase 0+1`, "warn");
  }

  await invokeAgent(cli, "researcher", assetContext, args, extraText, runLog);
  printFlavour("researcher_done");
}
```

---

### 4. Modifica il loop principale in `main()`

Trova il blocco nel loop `for` che chiama `runResearcherPhase`:

```javascript
    try {
      await runResearcherPhase(args.cli, assetContext, args, bundlePath, index > 0, runLog, resumeHint);
    } catch (err) {
```

Sostituiscilo con:

```javascript
    try {
      await runResearcherPhase(args.cli, assetContext, args, bundlePath, index > 0, runLog, resumeHint, globalSignalSet);
    } catch (err) {
```

Poi trova il blocco **subito prima** del loop `for` che gestisce gli asset
(la riga `for (let index = startAssetIndex; ...`). Aggiungi questa riga
immediatamente prima del `for`:

```javascript
  // Signal set condiviso tra tutte le asset pass — si accumula durante il pipeline
  const globalSignalSet = new Set();
```

---

### 5. Aggiungi il signal detection post-pass nel loop principale

Trova il blocco `try/catch` che wrappa `runResearcherPhase` nel loop degli asset.
Immediatamente **dopo** la chiamata `await runResearcherPhase(...)` (e prima del
blocco `catch`), aggiungi:

```javascript
      // Rileva nuovi signal dalla pass appena completata
      if (fs.existsSync(bundlePath)) {
        const { hasNew, signals } = detectReconSignals(bundlePath, globalSignalSet);
        if (hasNew) {
          logEvent(runLog, `Adaptive recon: ${signals.length} new signal(s) detected after researcher pass`);
          process.stdout.write(`  ${C.cyan}[adaptive]${C.reset} ${signals.length} new recon signal(s) — will focus next pass\n`);
          for (const s of signals) {
            process.stdout.write(`    ${C.dim}• ${s}${C.reset}\n`);
          }
        }
      }
```

---

### 6. Aggiungi adaptive loop tra researcher e dual researcher pass

Trova questo blocco nel `main()`:

```javascript
  runCommand("node", ["scripts/validate-bundle.js", bundlePath]);
  await runDualResearcherPass(context, bundlePath, runLog);
```

Sostituiscilo con:

```javascript
  runCommand("node", ["scripts/validate-bundle.js", bundlePath]);

  // Adaptive self-check: se il bundle ha nuovi signal ad alto valore
  // rispetto all'inizio del pipeline, aggiungi un hint al dual researcher pass
  {
    const reconUpdatePath = context.intelligenceDir
      ? path.join(context.intelligenceDir, "recon_updates.json")
      : null;
    if (globalSignalSet.size > 0 && reconUpdatePath && fs.existsSync(reconUpdatePath)) {
      logEvent(runLog, `Adaptive recon: ${globalSignalSet.size} total signal(s) accumulated — injecting into dual pass`);
    }
  }

  await runDualResearcherPass(context, bundlePath, runLog);
```

---

## VERIFICA FINALE

Dopo aver applicato tutte le modifiche, esegui:

```bash
node --check scripts/run-pipeline.js && echo "Syntax OK"
```

Poi verifica che le nuove funzioni siano presenti:

```bash
grep -n "detectReconSignals\|buildAdaptiveReconHint\|globalSignalSet\|adaptive recon\|Adaptive recon" \
  scripts/run-pipeline.js
```

Risultato atteso: almeno 8 hit.

Esegui anche un test di smoke del pipeline su un target esistente con `--resume`
per verificare che il resume non sia rotto dall'aggiunta dei nuovi parametri:

```bash
node scripts/run-pipeline.js --target 1 --cli claude --resume 2>&1 | head -20
```

Nessun altro file deve essere stato modificato.
