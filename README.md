# 🛡️ OmniScanner

**OmniScanner** è un motore di analisi difensiva locale e di Threat Intelligence leggero scritto in Python. È progettato per analizzare file sospetti (come PDF e Immagini) alla ricerca di artefatti malevoli latenti, verificare la catena di redirect degli URL e interfacciarsi con il cloud di VirusTotal per il controllo degli hash.

---

## 🚀 Funzionalità Principali

* **🔍 Analisi Strutturale PDF:** Identifica tag critici come `/JavaScript`, `/OpenAction` o `/EmbeddedFiles` che potrebbero innescare l'esecuzione automatica di exploit.
* **🖼️ Polyglot & Web Shell Detection:** Scansiona file immagine (`.png`, `.jpg`, ecc.) alla ricerca di payload nascosti, codice PHP (`<?php`, `eval`) o comandi PowerShell annidati nei metadati EXIF.
* **🌐 URL Redirect Tracker:** Traccia la catena completa dei reindirizzamenti di un link fino a individuare l'endpoint finale, segnalando il download automatico di estensioni pericolose (`.exe`, `.scr`, `.vbs`).
* **☁️ VirusTotal Core Integration:** Calcola l'hash SHA-256 dei file e interroga in tempo reale le API di VirusTotal per ottenere dettagli completi sulle definizioni dei malware.

---

## 🛠️ Requisiti e Installazione

Assicurati di avere Python 3 installato sul tuo sistema operativo.

1. Clona il repository:
   ```bash
   git clone [https://github.com/vito-dev-null/OmniScanner.git](https://github.com/vito-dev-null/OmniScanner.git)
   cd OmniScanner
