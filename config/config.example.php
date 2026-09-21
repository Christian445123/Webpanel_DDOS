<?php
/**
 * Konfiguration des VSRP DDoS Monitor.
 * Diese Datei nach config.php kopieren und die Werte eintragen.
 * config.php ist in .gitignore und wird NICHT eingecheckt (enthält Zugangsdaten).
 */

return [
    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'database' => 'vsrp_ddos',
        'username' => 'vsrp_ddos',
        'password' => '',
        'charset' => 'utf8mb4',
    ],

    // Zufälliger, langer String zur Absicherung der Web-Sessions (z. B. mit bin2hex(random_bytes(32)) erzeugen)
    'app_key' => 'CHANGE_ME_TO_A_RANDOM_64_CHAR_STRING',

    // Anzeigename und Basis-URL (für Links in E-Mail/Discord-Benachrichtigungen), z. B. https://ddos.viennastaterp.at
    'app_name' => 'VSRP DDoS Monitor',
    'base_url' => 'https://ddos.example.at',

    // Zeitzone für Anzeige/Auswertung
    'timezone' => 'Europe/Vienna',
];
