# VSRP DDoS Monitor – Web-Anwendung (PHP)

Erkennt (D)DoS-artige Netzwerklast auf dem Server, benachrichtigt per E-Mail und Discord und
schlägt Blockierbefehle für auffällige IP-Adressen vor. **Blockiert nichts automatisch** –
der Spiele-Server läuft ununterbrochen im Hintergrund weiter, ein Administrator entscheidet
und führt Befehle bei Bedarf manuell aus (oder markiert sie über den C#-Admin-Client).

Kein Composer, keine Framework-Abhängigkeit – reines PHP 8.1+, PDO/MySQL, `curl`.

## Architektur

- **`bin/collector.php`** – Dauerhaft laufender Hintergrunddienst (systemd), misst alle paar
  Sekunden Bandbreite (`/proc/net/dev`) und Verbindungen (`ss -Htan`), wertet Schwellwerte aus,
  legt Vorfälle (`incidents`) und auffällige IPs (`suspects`) an und löst Benachrichtigungen aus.
  Braucht keine Root-Rechte (nur Leserechte auf `/proc/net/dev` und Ausführrecht für `ss`).
- **`public/`** – Web-Dashboard (Login, Live-Status, Vorfallshistorie, Einstellungen,
  API-Schlüssel-Verwaltung) + REST-API (`public/api/`) für den C#-Admin-Client.
- **`src/`** – Anwendungslogik (Erkennung, Benachrichtigung, Datenbank, Auth).

Web-Anwendung und Collector-Dienst laufen unabhängig voneinander und teilen sich nur die Datenbank.

## Installation

1. **Datenbank anlegen** und Schema einspielen:
   ```bash
   mysql -u root -p -e "CREATE DATABASE vsrp_ddos CHARACTER SET utf8mb4;"
   mysql -u root -p vsrp_ddos < db/schema.sql
   ```
2. **Konfiguration**: `config/config.example.php` nach `config/config.php` kopieren und
   Datenbankzugang, `app_key` (Zufallsstring) und `base_url` eintragen.
3. **Admin-Benutzer anlegen**:
   ```bash
   php bin/create_admin.php admin
   ```
4. **Webserver**: DocumentRoot muss auf `public/` zeigen (Apache mit `mod_rewrite`, oder Nginx
   mit entsprechendem `try_files`/PHP-FPM-Block). `config/`, `src/`, `db/`, `bin/` liegen
   außerhalb von `public/` und sind damit nicht über den Browser erreichbar.

   Nginx-Beispiel:
   ```nginx
   root /var/www/vsrp-ddos/public;
   index index.php;
   location / { try_files $uri $uri/ /index.php?$args; }
   location /api/ { try_files $uri /api/index.php?r=$1&$args; }
   location ~ \.php$ {
       include fastcgi_params;
       fastcgi_pass unix:/run/php/php8.2-fpm.sock;
       fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
   }
   ```
5. **Collector-Dienst einrichten** (läuft dauerhaft im Hintergrund):
   ```bash
   sudo cp systemd/vsrp-ddos-collector.service /etc/systemd/system/
   # Pfade in der Datei anpassen (WorkingDirectory/ExecStart) und ggf. den User
   sudo systemctl daemon-reload
   sudo systemctl enable --now vsrp-ddos-collector
   sudo journalctl -u vsrp-ddos-collector -f
   ```
6. Im Dashboard unter **Einstellungen** Schwellwerte, SMTP und den Discord-Webhook eintragen,
   unter **API-Zugang** einen Schlüssel für den C#-Admin-Client erstellen.

> **Hinweis (Apache/PHP-FPM):** Der `Authorization`-Header wird von Apache standardmäßig nicht an
> PHP-FPM weitergereicht. Falls der C#-Client "401 unauthorized" meldet, im vHost oder in
> `public/.htaccess` ergänzen: `CGIPassAuth On` (Apache 2.4.13+) oder eine Rewrite-Regel
> `RewriteRule .* - [E=HTTP_AUTHORIZATION:%{HTTP:Authorization}]`.

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
