<?php

ini_set('display_errors', 1);
error_reporting(E_ALL);
error_reporting(E_ALL & ~E_DEPRECATED);

require_once __DIR__ . '/../bootstrap.php';


use Firewall\Database;
use Firewall\ReportGenerator;

try {
    $db = new Database();
    $pdo = $db->getConnection();

    $generator = new ReportGenerator($pdo);

    // Crear directorio de informes si no existe
    $dirInformes = __DIR__ . '/../../tmp';
    if (!is_dir($dirInformes)) {
        mkdir($dirInformes, 0755, true);
    }

    // Nombre del archivo con la fecha del informe
    $archivo = $dirInformes . '/informe_ejecutivo_' . date('Ym') . '.docx';

    // Generar el informe mensual
    $rutaGenerada = $generator->generarMensual($archivo);

    echo "Informe generado con éxito: " . htmlspecialchars($rutaGenerada);
} catch (Exception $e) {
    echo "Error al generar el informe Word: " . htmlspecialchars($e->getMessage());
}
