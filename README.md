# Cryptodude 🔐

**Cryptodude** ist ein experimentelles Projekt zum **client-seitigen Verschlüsseln von HTML-Inhalten** in **einer einzigen Datei** – komplett **offline**, ohne Server, ohne Cloud.

Der verschlüsselte Inhalt wird im Browser erst nach Eingabe eines Passworts entschlüsselt und in einer **Sandbox** angezeigt.

> Ziel des Projekts ist **Lernen & Experimentieren** mit moderner Kryptografie im Browser –  
> nicht der Ersatz für professionelle Passwort-Manager oder sichere Server-Systeme.

---

## ✨ Features

- 🔒 **AES-CCM Verschlüsselung** (SJCL-kompatibel)
- 🔑 **PBKDF2-HMAC-SHA256** mit hoher Iterationszahl
- 🧠 **Offline-fähig** (eine einzelne HTML-Datei)
- 🧪 Ideal zum **Ausprobieren & Lernen**
- 🛡️ **Sandboxed Rendering** des entschlüsselten Inhalts (keine Scripts, keine Exfiltration)
- 📄 Beliebiger HTML-Inhalt als Payload

---

## 🔧 Projektaufbau

```
cryptodude/
├── template.html      # Entschlüsselungs-Viewer (Browser)
├── cryptodude_encrypt.py  # Python-Tool zum Verschlüsseln von HTML
├── README.md
```

---

## 🚀 Verwendung

### 1️⃣ HTML verschlüsseln (lokal)

```bash
pip install cryptography
python cryptodude_encrypt.py geheim.html -o data.json
```

Alternativ Passwort per Environment Variable:

```bash
export CRYPTODUDE_PASSWORD="sehr-langes-sicheres-passwort"
python cryptodude_encrypt.py geheim.html
```

---

### 2️⃣ Viewer erstellen

- Öffne `template.html`
- Ersetze dort den Platzhalter:

```js
const DATA_JSON_STRING = '{ ... }';
```

mit dem JSON-String aus `data.json`.

---

### 3️⃣ Öffnen & Entschlüsseln

- Öffne `template.html` im Browser (offline möglich)
- Passwort eingeben
- Inhalt wird entschlüsselt und angezeigt

---

## 🔐 Sicherheitsmodell (wichtig!)

Cryptodude bietet **kryptografischen Schutz**, aber **keinen Zugriffsschutz**.

### Was es gut kann

- Schutz gegen **Neugierde / Zufallszugriffe**
- Offline-Verschlüsselung
- Keine Server-Abhängigkeiten
- Keine Drittanbieter

### Was es **nicht** schützt

- ❌ Offline-Bruteforce, wenn jemand die Datei besitzt
- ❌ Zielgerichtete Angriffe mit schwachen Passwörtern
- ❌ Manipulation der HTML-Datei durch Dritte
- ❌ Authentizität („ist das wirklich vom Autor?“)

> **Wichtig:**  
> Wer die Datei besitzt, kann unbegrenzt offline Passwort-Versuche durchführen.  
> Die Sicherheit hängt maßgeblich von **Passwortlänge & KDF-Parametern** ab.

---

## 🧠 Empfohlene Parameter

Standardmäßig verwendet:

- `PBKDF2 iterations ≥ 600.000`
- `AES-CCM Auth-Tag = 128 bit`
- Lange Passphrases (z. B. mehrere zufällige Wörter)

Für **ernsthafte Geheimnisse**:

- Argon2id oder scrypt (nicht Teil dieses Projekts)
- Server-seitiger Login / Rate-Limiting
- Signaturen zur Authentizität

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

---

## 🤝 Mitmachen / Ideen

Pull Requests, Verbesserungen und Diskussionen sind willkommen – insbesondere zu:

- moderneren KDFs (Argon2)
- UX-Verbesserungen
- Signatur-Validierung
- automatischem Builder (HTML → Single-File-Viewer)

---

**Have fun breaking and improving it.**
