#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Legt den ersten (oder einen weiteren) Admin-Benutzer für das Web-Dashboard an.
 * Aufruf: php bin/create_admin.php <benutzername>
 * Fragt danach interaktiv nach dem Passwort.
 */

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    exit('Nur über die Kommandozeile ausführbar.');
}

require dirname(__DIR__) . '/autoload.php';

use Vsrp\Ddos\Database;

$username = trim($argv[1] ?? '');
if ($username === '') {
    fwrite(STDERR, "Aufruf: php bin/create_admin.php <benutzername>\n");
    exit(1);
}

fwrite(STDOUT, 'Passwort (mind. 10 Zeichen): ');
system('stty -echo');
$password = trim((string)fgets(STDIN));
system('stty echo');
fwrite(STDOUT, "\n");

if (strlen($password) < 10) {
    fwrite(STDERR, "Passwort muss mindestens 10 Zeichen haben.\n");
    exit(1);
}

$db = Database::connection();
$stmt = $db->prepare(
    'INSERT INTO users (username, password_hash) VALUES (:u, :p)
     ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash)'
);
$stmt->execute(['u' => $username, 'p' => password_hash($password, PASSWORD_DEFAULT)]);

fwrite(STDOUT, "Benutzer '$username' angelegt/aktualisiert.\n");
