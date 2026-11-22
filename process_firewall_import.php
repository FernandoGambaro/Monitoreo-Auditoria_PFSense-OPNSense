<?php
ini_set('display_errors', 0); // Ocultar errores crudos en producción para evitar salidas antes de header()
ini_set('display_startup_errors', 0);
error_reporting(E_ALL);

require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

try {
    $firewallId = (int) ($_POST['firewall_id'] ?? 0);
    $tipoFirewall = $_POST['tipo_firewall'] ?? 'opnsense';
    $cantidad = (int) ($_POST['cantidad'] ?? 1000);

    if ($firewallId <= 0) {
        throw new Exception("Debe seleccionar un firewall válido para continuar.");
    }

    $db = new Database();
    $pdo = $db->getConnection();

    // Seleccionar la clase importadora adecuada según el tipo e inyectar el firewall_id
    if (strtolower($tipoFirewall) === 'pfsense') {
        $importador = new PfSenseLogImporter($pdo, $firewallId);
    } else {
        $importador = new OpnsenseLogImporter($pdo, $firewallId);
    }

    // Ejecutamos la importación
    $resultado = $importador->import($cantidad);

    $_SESSION['msg_tipo'] = 'success';
    $_SESSION['msg_texto'] = sprintf(
        "Importación completada con éxito. Procesados: %d | Insertados: %d | Duplicados omitidos: %d",
        $resultado['procesados'],
        $resultado['insertados'],
        $resultado['duplicados']
    );

} catch (Throwable $e) {
    // Registrar el error internamente en los logs del servidor
    error_log("Error en importación de logs: " . $e->getMessage() . " en " . $e->getFile() . ":" . $e->getLine());

    $_SESSION['msg_tipo'] = 'danger';
    $_SESSION['msg_texto'] = 'Error al importar registros: ' . $e->getMessage();
}

// Redirección limpia de vuelta al formulario
header('Location: import_firewall.php');
exit;