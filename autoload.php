<?php

declare(strict_types=1);

/**
 * Einfacher PSR-4-Autoloader für den Namespace Vsrp\Ddos (kein Composer nötig).
 * Vsrp\Ddos\Models\Setting -> src/Models/Setting.php
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'Vsrp\\Ddos\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $relative = substr($class, strlen($prefix));
    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';
    if (is_file($path)) {
        require $path;
    }
});

require __DIR__ . '/src/Config.php';
Vsrp\Ddos\Config::all();
