<?php

declare(strict_types=1);

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

session_start();
date_default_timezone_set("America/Montevideo");

// Definir una constante raíz si no la tienes en entorno.php
define('BASE_PATH', __DIR__);

require_once BASE_PATH . '/vendor/autoload.php';
require_once BASE_PATH . '/entorno.php';

//require_once BASE_PATH . '/config/database.php';

require_once BASE_PATH . '/classes/Database.php';
require_once BASE_PATH . '/classes/Utils.php';
require_once BASE_PATH . '/classes/GeoIp.php';
require_once BASE_PATH . '/classes/FirewallParser.php';
require_once BASE_PATH . '/classes/ExcelImporter.php';
require_once BASE_PATH . '/classes/SenseLogImporter.php';
require_once BASE_PATH . '/classes/Dashboard.php';
require_once BASE_PATH . '/classes/Statistics.php';
require_once BASE_PATH . '/classes/ReportGenerator.php';
require_once BASE_PATH . '/classes/AlertEngine.php';

require_once BASE_PATH . '/classes/Encryption.php';
