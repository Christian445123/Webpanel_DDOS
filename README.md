# VSRP DDoS Monitor – Web-Anwendung (PHP)

Erkennt (D)DoS-artige Netzwerklast auf dem Server, benachrichtigt per E-Mail und Discord und
schlägt Blockierbefehle für auffällige IP-Adressen vor. **Blockiert nichts automatisch** –
der Spiele-Server läuft ununterbrochen im Hintergrund weiter, ein Administrator entscheidet
und führt Befehle bei Bedarf manuell aus (oder markiert sie über den C#-Admin-Client).

Kein Composer, keine Framework-Abhängigkeit – reines PHP 8.1+, PDO/MySQL, `curl`.

## Architektur

Flache Struktur wie bei U19 (`AFBÖ/U19`) – **kein separater `public/`-Ordner, kein Anpassen der
CloudPanel-/vHost-Konfiguration nötig.** Der komplette Ordnerinhalt wird 1:1 per SFTP in das
Website-Root-Verzeichnis der CloudPanel-Seite hochgeladen (dort, wo sonst z. B. die
Platzhalter-`index.php` liegt), fertig.

- **`bin/collector.php`** – Dauerhaft laufender Hintergrunddienst (systemd), misst alle paar
  Sekunden Bandbreite (`/proc/net/dev`) und Verbindungen (`ss -Htan`), wertet Schwellwerte aus,
  legt Vorfälle (`incidents`) und auffällige IPs (`suspects`) an und löst Benachrichtigungen aus.
  Braucht keine Root-Rechte (nur Leserechte auf `/proc/net/dev` und Ausführrecht für `ss`).
  Nur über die Kommandozeile ausführbar (nicht über den Browser), zusätzlich per `.htaccess`
  und `bin/.htaccess` gesperrt.
- **Web-Dashboard** (`index.php`, `login.php`, `dashboard.php`, `incidents.php`, `incident.php`,
  `settings.php`, `api_keys.php`) + **REST-API** (`api/`) für den C#-Admin-Client.
- **`src/`** – Anwendungslogik (Erkennung, Benachrichtigung, Datenbank, Auth). Über `.htaccess`
  vor direktem Browser-Zugriff gesperrt (`RewriteRule ^src/ - [F,L]`); die Klassen darin
  deklarieren ohnehin nur Code und geben bei direktem Aufruf keine Daten aus.
- **`.env`** – Zugangsdaten (Datenbank, SMTP, Discord, `APP_KEY`). Per `.htaccess` gesperrt
  (`<FilesMatch "^\.env$"> Require all denied </FilesMatch>`), zusätzlich nie über Git verteilt.

Web-Anwendung und Collector-Dienst laufen unabhängig voneinander und teilen sich nur die Datenbank.

## Installation

1. **Datenbank anlegen** und Schema einspielen:
   ```bash
   mysql -u root -p -e "CREATE DATABASE vsrp_ddos CHARACTER SET utf8mb4;"
   mysql -u root -p vsrp_ddos < db/schema.sql
   ```
2. **Konfiguration**: `.env.example` nach `.env` kopieren und ausfüllen (Datenbankzugang, `APP_KEY`,
   `BASE_URL`, SMTP, Discord-Webhook). **`.env` enthält Zugangsdaten, wird nicht eingecheckt
   (siehe `.gitignore`) und darf nur per SFTP direkt auf den Server übertragen werden — niemals
   per `git push`/`pull`.** `APP_KEY` erzeugen z. B. mit:
   ```bash
   php -r "echo bin2hex(random_bytes(32));"
   ```
3. **Admin-Benutzer anlegen**:
   ```bash
   php bin/create_admin.php admin
   ```
4. **Dateien hochladen**: kompletten Ordnerinhalt per SFTP in das Website-Root der CloudPanel-Seite
   kopieren (keine vHost-/Document-Root-Änderung nötig – Schutz sensibler Dateien läuft über
   `.htaccess`, siehe oben).
5. **Collector-Dienst einrichten** (läuft dauerhaft im Hintergrund):
   ```bash
   sudo cp systemd/vsrp-ddos-collector.service /etc/systemd/system/
   # Platzhalter <siteuser> und den Pfad in der Datei anpassen (CloudPanel-Seitenbenutzer)
   sudo systemctl daemon-reload
   sudo systemctl enable --now vsrp-ddos-collector
   sudo journalctl -u vsrp-ddos-collector -f
   ```
6. Im Dashboard unter **Einstellungen** die Erkennungs-Schwellwerte anpassen (SMTP/Discord kommen
   aus `.env`, siehe oben) und unter **API-Zugang** einen Schlüssel für den C#-Admin-Client erstellen.

> **Hinweis (Authorization-Header):** Manche Apache/PHP-FPM-Konfigurationen reichen den
> `Authorization`-Header nicht automatisch durch. `api/.htaccess` enthält dafür bereits die
> nötige Rewrite-Regel; falls der C#-Client dennoch "401 unauthorized" meldet, zusätzlich im
> vHost `CGIPassAuth On` (Apache 2.4.13+) ergänzen.

## Erkennung & Gegenmaßnahme – bewusste Design-Entscheidung

Ein "Gegenangriff" (aktive Rückattacke auf die Angreifer-IP) ist in praktisch jeder
Rechtsordnung illegal und bei DDoS-Angriffen technisch meist wirkungslos bis kontraproduktiv,
da die Quell-IPs häufig gespooft sind oder gekaperten Drittrechnern (Botnet) gehören – ein
Gegenangriff würde also unbeteiligte Dritte treffen. Diese Anwendung implementiert daher
**ausschließlich defensive, passive Erkennung**:

- Schwellwertbasierte Erkennung über Bandbreite, Paketrate, Verbindungsanzahl, SYN-RECV-Anzahl
  und Verbindungen je Einzel-IP (jeweils in den Einstellungen anpassbar).
- Alarmierung per E-Mail und Discord-Webhook, inkl. Zusammenfassung ähnlich der
  Provider-Abuse-Mails (Top-IPs, Verbindungszahlen).
- Vorgeschlagene, aber **nicht automatisch ausgeführte** `nft`/`iptables`-Blockierbefehle je
  auffälliger IP – zur manuellen Ausführung durch einen Administrator, damit der laufende
  Spiele-Server nicht versehentlich durch Fehlalarme gestört wird.

## Wartung

- Alte Messwerte (außerhalb von Vorfällen) werden automatisch nach `samples_retention_days`
  Tagen gelöscht (Standard 14, einstellbar).
- Logs des Collector-Dienstes: `journalctl -u vsrp-ddos-collector`.
