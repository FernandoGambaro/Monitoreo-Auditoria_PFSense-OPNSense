<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Cargar el archivo centralizador de la raíz
require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

try {

    if (!isset($_FILES['archivo'])) {
        throw new Exception(
            'No se recibió archivo.'
        );
    }

    echo '<pre>';

    print_r($_FILES);

    $db = new Database();

    $importer =
        new ExcelImporter(
            $db->getConnection()
        );

    $resultado =
        $importer->import(
            $_FILES['archivo']
        );

    print_r($resultado);

    echo '</pre>';

} catch (Exception $e) {

    echo '<h2>ERROR</h2>';

    echo '<pre>';

    echo $e->getMessage();

    echo PHP_EOL;

    echo $e->getTraceAsString();

    echo '</pre>';
}