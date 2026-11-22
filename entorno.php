<?php

function loadEnv($path)
{
if (!file_exists($path)) {
        return;
    }
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
            putenv(sprintf('%s=%s', $name, $value));
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}

loadEnv($_SERVER['DOCUMENT_ROOT'] . '/firewall/.env');

$user = $_ENV['DBF_USER'] ?? '';
$pass = $_ENV['DBF_PASS'] ?? '';
$db   = $_ENV['DBF_BASE'] ?? '';
$host = $_ENV['DBF_HOST'] ?? '';

$ip = $_ENV['PFSENSE_IP'] ?? '';
$pfsenseUser = $_ENV['PFSENSE_USER'] ?? '';
$pfsensePass = $_ENV['PFSENSE_PASS'] ?? '';

define('DB_HOST', $host);
define('DB_NAME', $db);
define('DB_USER', $user);
define('DB_PASS', $pass);

define('PFSENSE_IP', $ip);
define('PFSENSE_USER', $pfsenseUser);
define('PFSENSE_PASS', $pfsensePass);