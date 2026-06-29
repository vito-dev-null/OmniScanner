import os
import sys
import hashlib
import requests
import re
import struct
import json
from urllib.parse import urlparse
from io import BytesIO

# File e librerie necessari:
# pip install requests

class ThorThreatEngine:
    """
    ThorThreatEngine è un motore di analisi difensiva per identificare e classificare
    minacce in file locali e URL, utilizzando tecniche di hashing, intelligence cloud (VirusTotal),
    analisi strutturale dei PDF, rilevamento di polyglot images e cattive pratiche sugli URL.
    """

    def __init__(self, vt_api_key=None):
        self.VT_API_KEY = vt_api_key
        self.session = requests.Session()
        self.session.timeout = 10

    def _calculate_sha256(self, filepath):
        """Calcola l'hash SHA-256 di un file."""
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            print(f"[ERRORE] Impossibile calcolare l'hash del file: {e}")
            return None

    def _check_virustotal_hash(self, file_hash):
        """Controlla l'hash su VirusTotal e restituisce risultati dettagliati."""
        if not self.VT_API_KEY:
            print("[ATTENZIONE] Nessuna chiave API VirusTotal fornita. Saltato controllo.")
            return None

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.VT_API_KEY}
        try:
            response = self.session.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())
                threat_label = data['data'].get('attributes', {}).get('popular_threat_classification', {}).get(
                    'suggested_threat_label', 'N/D')
                category = data['data'].get('attributes', {}).get('popular_threat_classification', {}).get(
                    'suggested_threat_category', 'N/D')

                return {
                    "status": "Maligno" if malicious > 0 else "Pulito",
                    "detection_rate": f"{malicious}/{total}",
                    "category": category,
                    "name": threat_label
                }
            elif response.status_code == 404:
                return {"status": "Sconosciuto", "detection_rate": "0/0", "category": "N/D", "name": "N/D"}
            else:
                print(f"[VT ERRORE] Risposta API: {response.status_code}")
                return None
        except Exception as e:
            print(f"[VT ERRORE] {e}")
            return None

    def analyze_pdf(self, filepath):
        """Analizza un file PDF alla ricerca di elementi malevoli."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            alerts = []
            suspicious_tags = [r'/JavaScript', r'/OpenAction', r'/AA\b', r'/EmbeddedFiles', r'/XFA']
            for tag in suspicious_tags:
                if re.search(tag, content):
                    alerts.append({
                        "name": tag.strip('/'),
                        "risk": "Potrebbe causare esecuzione automatica di script o payload.",
                        "severity": "Alto"
                    })

            print("=== ANALISI PDF ===")
            if alerts:
                for alert in alerts:
                    print(f"[ALLARME] {alert['name']}: {alert['risk']}")
            else:
                print("[INFO] Nessun elemento malevolo rilevato nel PDF.")
            return alerts
        except Exception as e:
            print(f"[ERRORE PDF] {e}")

    def analyze_image(self, filepath):
        """Analizza immagini alla ricerca di polyglot e web shells."""
        try:
            with open(filepath, 'rb') as f:
                content = f.read()

            # Ottimizzato: rimosse stringhe troppo corte come 'sh' o 'bash' per evitare falsi positivi grafici
            suspicious_strings = [b"<?php", b"eval(", b"base64_decode", b"powershell", b"bypassexecutionpolicy"]
            findings = []
            for phrase in suspicious_strings:
                if phrase in content:
                    findings.append(phrase.decode())

            # Controllo EXIF minimale
            exif_start = content.find(b"Exif")
            if exif_start != -1:
                exif_data = content[exif_start:exif_start + 512]
                if any(s in exif_data for s in suspicious_strings):
                    findings.append("[EXIF sospetto]")
            
            print("=== ANALISI IMMAGINE ===")
            if findings:
                print("[ALLARME] Trovati elementi sospetti:", ", ".join(findings))
            else:
                print("[INFO] Nessun dato sospetto trovato.")
            return findings
        except Exception as e:
            print(f"[ERRORE IMMAGINE] {e}")

    def analyze_url(self, url):
        """Analizza un URL alla ricerca di redirect e URL dannosi."""
        print("=== ANALISI URL ===")
        chain = []
        current_url = url
        headers = {"User-Agent": "Mozilla/5.0"}

        try:
            while len(chain) < 10:  # Limite max redirect
                chain.append(current_url)
                res = self.session.head(current_url, headers=headers, allow_redirects=False)
                location = res.headers.get("Location")
                if not location:
                    break
                current_url = location if location.startswith("http") else f"{urlparse(current_url).scheme}://{urlparse(current_url).netloc}{location}"

            final_url = chain[-1]
            final_ext = os.path.splitext(urlparse(final_url).path)[-1].lower()

            dangerous_extensions = [".exe", ".scr", ".vbs", ".lnk", ".zip", ".iso"]
            is_dangerous = final_ext in dangerous_extensions

            print("Catena di redirect: ", " -> ".join(chain))
            if is_dangerous:
                print(f"[ALLARME] L'URL punta a un file pericoloso: {final_ext.upper()}")
            else:
                print("[INFO] Nessuna estensione pericolosa rilevata.")

            if self.VT_API_KEY:
                try:
                    vt_scan_url = "https://www.virustotal.com/api/v3/urls"
                    payload = {"url": url}
                    headers_vt = {"x-apikey": self.VT_API_KEY}
                    scan_response = self.session.post(vt_scan_url, data=payload, headers=headers_vt)
                    if scan_response.status_code == 200:
                        analysis_id = scan_response.json()["data"]["id"]
                        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
                        print("[VT] Analisi inviata. Controlla:", result_url)
                    else:
                        print(f"[VT] Errore in analisi URL: {scan_response.status_code}")
                except Exception as e:
                    print(f"[VT ERROR] {e}")

        except Exception as e:
            print(f"https://dictionary.cambridge.org/us/dictionary/italian-english/errore {e}")

    def run_analysis(self, target):
        """Punto di ingresso per l'analisi di file o URL."""
        if target.startswith("http"):
            self.analyze_url(target)
        elif os.path.isfile(target):
            file_ext = os.path.splitext(target)[1].lower()
            print(f"[INFO] File identificato come: {file_ext}")
            if file_ext in [".pdf"]:
                self.analyze_pdf(target)
            elif file_ext in [".png", ".jpg", ".jpeg", ".gif"]:
                self.analyze_image(target)
            else:
                print("[INFO] File non supportato per analisi specifica - tentativo hash...")

            # Hash e controllo su VT
            filehash = self._calculate_sha256(target)
            if filehash:
                print(f"[INFO] SHA-256: {filehash}")
                vt_result = self._check_virustotal_hash(filehash)
                if vt_result:
                    print(f"[VT RISULTATO] Stato: {vt_result['status']}, "
                          f"Rilevamento: {vt_result['detection_rate']}, "
                          f"Categoria: {vt_result['category']}, "
                          f"Nome: {vt_result['name']}")
        else:
            print("[ERRORE] Input non valido: non è un file né un URL.")

def main():
    # Recupera la chiave API dalle variabili d'ambiente per sicurezza
    api_key = os.getenv("VT_API_KEY", None)  

    engine = ThorThreatEngine(api_key)

    # --- ESEMPI DI TEST ---
    # Inserisci qui il percorso di un file reale o un URL per testare lo script
    print("=== Esecuzione test URL ===")
    engine.run_analysis("http://example.com/malware.exe")

if __name__ == "__main__":
    main()