# AnyDesk IP-Leak-Sicherheitslücke CVE-2024-52940


## 🎤 README-Übersetzungen
- [English](README.md)
- [Deutsch](README.de.md)
- [فارسی](README.fa.md)

## 📸 Screenshot

 <p align="center"><img src="abdal-anydesk-remote-ip-detector-proof.gif?raw=true"></p>

## 🎥 Proof of Concept Videos

Um die **AnyDesk IP-Leak-Sicherheitslücke** in Aktion zu sehen, können Sie die Demonstrationsvideos des PoCs unten herunterladen:

- [📥 Download Proof 01](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof.mp4)
- [📥 Download Proof 02](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof-2.mp4)
- Empfohlen - [📥 Download Proof 03](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/raw/main/abdal-anydesk-remote-ip-detector-proof-3.mp4)

Diese Videos zeigen, wie die Sicherheitslücke funktioniert und die Auswirkungen auf die Privatsphäre von IP-Adressen.

## 💎 Einführung
Der **Abdal AnyDesk Remote IP Detector** ist ein Proof-of-Concept (PoC)-Tool, das eine **Zero-Day-Sicherheitslücke** ausnutzt, die am **27. Oktober 2024** in der Funktion „Allow Direct Connections“ von AnyDesk entdeckt wurde. Wenn diese Option aktiviert und der Verbindungsport nur auf dem System des Angreifers auf 7070 eingestellt ist, kann ein Angreifer die öffentliche IP-Adresse des Ziels allein mit der AnyDesk-ID abrufen, ohne dass am Zielsystem Konfigurationsänderungen erforderlich sind. Wenn beide Systeme im selben Netzwerk sind, kann der Angreifer auch die private IP-Adresse des Ziels abrufen.

## 💀 Sicherheitsübersicht
Diese **Zero-Day-Sicherheitslücke** in der „Allow Direct Connections“-Funktion von AnyDesk legt sensible IP-Informationen des Ziels offen. Angreifer können diesen Fehler ausnutzen, um die öffentliche IP-Adresse und in bestimmten Fällen die private IP-Adresse des Zielsystems abzurufen. Diese Sicherheitslücke stellt erhebliche Datenschutzrisiken dar, insbesondere wenn Sicherheitskonfigurationen in Remote-Access-Tools nicht ausreichend geschützt sind.

Wenn die Option „Allow Direct Connections“ auf dem System des Angreifers aktiviert ist, gibt AnyDesk versehentlich die öffentliche IP-Adresse des Ziels im Netzwerkverkehr preis. Diese IP-Adresse kann durch Netzwerksniffing auf dem System des Angreifers leicht identifiziert werden. Wenn beide Systeme im selben lokalen Netzwerk sind, kann auch die private IP-Adresse des Ziels zugänglich sein. Das folgende Bild zeigt die Erfassung des Netzwerkverkehrs mithilfe des Abdal Sniffer-Tools und veranschaulicht, wie diese Informationen offengelegt werden.

<p align="center"><img src="vulnerability-overview-01.png?raw=true"></p>

### 🔍 CVE-Details
Diese Schwachstelle wurde offiziell als **CVE-2024-52940** registriert.  
Sie wurde unter dem Namen **Ebrahim Shafiei (EbraSha)** von **NIST** (National Institute of Standards and Technology), **Tenable** und **MITRE** eingereicht und registriert, einer Organisation, die die US-Regierung in wissenschaftlichen und technischen Bereichen berät.

Weitere Informationen finden Sie unter:
- [CVE-2024-52940-Seite bei NVD (NIST)](https://nvd.nist.gov/vuln/detail/CVE-2024-52940)
- [Tenable-CVE-Seite](https://www.tenable.com/cve/CVE-2024-52940)
- [MITRE-CVE-Seite](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-52940)


## ✨ Funktionen
* Abruf der öffentlichen IP-Adresse eines Remote-Systems, wenn die AnyDesk-ID bekannt ist.
* Erkennung der privaten IP innerhalb lokaler Netzwerkverbindungen.
* Schnelle Einrichtung und einfache Ausführung des PoCs.
* Keine komplexen Abhängigkeiten erforderlich.


## 🛠️ Entwicklungsumgebung
- **.NET 6**
- **Visual Studio 2022**


## 🔥 Anforderungen
Es sind keine speziellen Voraussetzungen erforderlich, um diesen PoC auszuführen.

## 📥 Download
Um die ausführbaren Versionen dieses PoCs herunterzuladen, besuchen Sie bitte die offizielle Releases-Seite auf GitHub. Dort finden Sie die kompilierte Version zur direkten Verwendung:

- [Download ausführbare PoC-Versionen von GitHub](https://github.com/ebrasha/abdal-anydesk-remote-ip-detector/releases)



## 📦 Einrichtung und Verwendung
1. **Direct Connections in AnyDesk aktivieren**: Öffnen Sie AnyDesk, gehen Sie zu Einstellungen > Verbindung und aktivieren Sie die Option „Allow direct connections“. Stellen Sie den Verbindungsport auf 7070 ein.
2. **PoC-Tool starten**: Führen Sie das Tool **Abdal AnyDesk Remote IP Detector** aus.
3. **Ziel-AnyDesk-ID eingeben**: Geben Sie die AnyDesk-ID des Zielsystems in Ihrer AnyDesk-Anwendung ein.
4. **IP-Abruf über Netzwerksniffing**: Nach Eingabe der Ziel-AnyDesk-ID überwacht das PoC-Tool automatisch den Netzwerkverkehr auf Ihrem System, um die öffentliche IP-Adresse des Ziels zu erkennen und anzuzeigen. Wenn beide Systeme im selben lokalen Netzwerk sind, wird auch die private IP-Adresse des Ziels angezeigt.


## 😎 Erwartete Ausgabe
Das Tool zeigt an:

* Die öffentliche IP-Adresse des Remote-Systems.
* Die private IP-Adresse, wenn beide Systeme sich im selben lokalen Netzwerk befinden.


## 🛑 Betroffene Versionen

Diese Sicherheitslücke betrifft **AnyDesk Version 8.1.0 und darunter**. Bislang gibt es keine veröffentlichte Version zur Behebung dieses Problems.


## ✅ Abhilfe
Leider gibt es derzeit keine Benutzerspezifische Lösung für diese Sicherheitslücke. Um dieses Problem vollständig zu beheben, ist ein Update oder Patch von der Entwicklungsteams von AnyDesk erforderlich.

## 🎖️ Anerkennung
- **Entdeckung des Bugs und PoC-Entwickler**: Ebrahim Shafiei (EbraSha)
- [Profil auf LinkedIn](https://www.linkedin.com/in/profshafiei/)


 
## ❤️ Spenden
Falls Ihnen dieses Projekt hilfreich erscheint und Sie die weitere Entwicklung unterstützen möchten, können Sie gerne eine Spende machen:
- [Hier spenden](https://ebrasha.com/abdal-donation)

## 🤵 Entwickler
Mit Leidenschaft entwickelt von **Ebrahim Shafiei (EbraSha)**
- **E-Mail**: Prof.Shafiei@Gmail.com
- **Telegram**: [@ProfShafiei](https://t.me/ProfShafiei)

## ☠️ Fehler melden
Falls Sie auf Probleme stoßen oder Schwierigkeiten bei der Konfiguration haben, können Sie sich per E-Mail an Prof.Shafiei@Gmail.com wenden. Sie können auch Probleme auf GitLab oder GitHub melden.

## ⚠️  Rechtlicher Hinweis
Dieses Proof-of-Concept (PoC) wird ausschließlich zu Bildungszwecken zur Verfügung gestellt. Die unbefugte Nutzung dieses Codes auf Systemen, die Ihnen nicht gehören oder für die Sie keine ausdrückliche Genehmigung zum Testen haben, ist illegal und unethisch. Durch die Verwendung dieses PoCs übernehmen Sie die volle Verantwortung für etwaigen Missbrauch oder Schäden, die daraus resultieren können. Der Autor übernimmt keine Haftung für Handlungen, die auf Grundlage der in diesem Repository bereitgestellten Informationen vorgenommen werden. Stellen Sie stets sicher, dass Sie vor jeglichen Sicherheitstests eine ordnungsgemäße Genehmigung besitzen.
