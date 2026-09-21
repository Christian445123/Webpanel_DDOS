<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;

header('Location: ' . (Auth::check() ? '/dashboard.php' : '/login.php'));
exit;
