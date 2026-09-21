<?php

declare(strict_types=1);

require __DIR__ . '/autoload.php';

use Vsrp\Ddos\Auth;

Auth::logout();
header('Location: /login.php');
exit;
