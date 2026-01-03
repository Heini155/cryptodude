# Cryptodude 🔐

**Cryptodude** ist ein experimentelles Projekt zum **client-seitigen Verschlüsseln von HTML-Inhalten** in **einer einzigen Datei** – komplett **offline**, ohne Server, ohne Cloud.

Der verschlüsselte Inhalt wird im Browser erst nach Eingabe eines Passworts entschlüsselt und in einer **Sandbox** angezeigt.

> Ziel des Projekts ist **Lernen & Experimentieren** mit moderner Kryptografie im Browser –  
> **nicht** der Ersatz für professionelle Passwort-Manager oder sichere Server-Systeme.

---

## ✨ Features

- 🔒 **AES-CCM Verschlüsselung** (SJCL-kompatibel)
- 🔑 **PBKDF2-HMAC-SHA256** mit hohen Iterationszahlen (Default: 600 000)
- 🧠 **Offline-fähig** (eine einzelne HTML-Datei)
- 🛡️ **Sandboxed Rendering** des entschlüsselten Inhalts  
  (keine Scripts, keine externen Requests)
- 📄 Beliebiger HTML-Inhalt als Payload
- 🧪 **pytest-Tests** für Kernfunktionen

---

## 🔧 Projektaufbau

```
cryptodude/
├── template.html              # Entschlüsselungs-Viewer (Browser)
├── cryptodude_encrypt.py      # Python-Encrypt-Tool (v1.1)
├── tests/
│   ├── conftest.py            # Fügt Projekt-Root zum Importpfad hinzu
│   └── test_crypto.py         # Unit-Tests
├── pyproject.toml
└── README.md
```

---

## 🚀 Verwendung

### 1️⃣ HTML verschlüsseln (lokal)

Abhängigkeiten installieren:
```bash
pip install cryptography
```

Empfohlene Variante (Passwort über stdin):
```bash
echo -n "sehr-langes-sicheres-passwort" | \
python cryptodude_encrypt.py geheim.html --password-stdin -o data.json
```

Alternativ über Environment-Variable:
```bash
export CRYPTODUDE_PASSWORD="sehr-langes-sicheres-passwort"
python cryptodude_encrypt.py geheim.html -o data.json
```

Interaktiv (getpass, kein Echo):
```bash
python cryptodude_encrypt.py geheim.html -o data.json
```

> ⚠️ `--password` als CLI-Argument ist **möglich**, aber **nicht empfohlen**,  
> da es in Shell-History und Prozess-Listen auftauchen kann.

---

### 2️⃣ Viewer vorbereiten

- Öffne `template.html`
- Ersetze dort den Platzhalter:

```js
const DATA_JSON_STRING = '{ ... }';
```

durch den JSON-String aus `data.json`.

---

### 3️⃣ Öffnen & Entschlüsseln

- `template.html` im Browser öffnen (offline möglich)
- Passwort eingeben
- Inhalt wird lokal entschlüsselt und angezeigt

---

## 🔐 Sicherheitsmodell (wichtig!)

Cryptodude bietet **kryptografischen Schutz**, aber **keinen Zugriffsschutz**.

### Was es gut kann
- Schutz gegen **Neugierde / Zufallszugriffe**
- Offline-Verschlüsselung ohne Drittanbieter
- Integrität & Authentizität des Ciphertexts (AEAD)

### Was es **nicht** schützt
- ❌ Offline-Bruteforce, wenn jemand die Datei besitzt
- ❌ Zielgerichtete Angriffe mit schwachen Passwörtern
- ❌ Authentizität des Autors („ist diese Datei wirklich von mir?“)
- ❌ Schutz vor absichtlich manipulierten Viewern

> **Wichtig:**  
> Wer die Datei besitzt, kann unbegrenzt offline Passwort-Versuche durchführen.  
> Sicherheit hängt maßgeblich von **Passwortlänge** und **KDF-Parametern** ab.

---

## 🧠 Empfohlene Parameter

Standard (v1.1 Default):
- `PBKDF2 iterations = 600.000`
- `AES-CCM Auth-Tag = 128 bit`
- Lange Passphrases (z. B. mehrere zufällige Wörter)

Guardrails:
- Warnung bei `< 200.000` Iterationen
- Abbruch bei `< 50.000`, außer `--allow-weak` ist gesetzt

---

## 🧪 Tests

Tests werden mit **pytest** ausgeführt.

Installation:
```bash
pip install pytest cryptography
```

Ausführen:
```bash
pytest -q
```

Getestet werden u. a.:
- CCM-Nonce-Berechnung (SJCL-kompatibel)
- Schlüsselableitung
- JSON-Serialisierung / Round-Trip

---

## 🧪 Typische Anwendungsfälle

✅ Geeignet für:
- Lern- & Demo-Projekte
- Private Notizen
- Rätsel / Geocaching
- „Eine Datei, die man nicht einfach öffnen kann“

❌ Nicht geeignet für:
- Passwort-Manager
- Hochsensible Daten
- Öffentliches Hosting mit echtem Geheimschutz

---

## ⚠️ Haftungsausschluss

Dieses Projekt ist **experimentell**.  
Es gibt **keine Garantie** für Sicherheit, Korrektheit oder Eignung für produktive Einsätze.

**Benutzung auf eigene Verantwortung.**

---

## 📜 Lizenz

MIT License  
(oder nach Bedarf anpassen)

---

## 🤝 Roadmap / Ideen

- Argon2id / scrypt als optionaler KDF
- One-Shot-Builder: `geheim.html → fertige template.html`
- Digitale Signaturen (Ed25519) für Authentizität
- UX-Verbesserungen (Dark-Mode, Progress-Anzeige)

---

**Have fun breaking and improving it.**
