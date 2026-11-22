<?php
// Asegurar ejecución exclusiva por CLI (Línea de comandos) o permitir ejecución controlada
if (php_sapi_name() !== 'cli' && !isset($_GET['token_secreto_seguro'])) {
    // Si prefieres permitir ejecución web protegida por token, puedes descomentar o ajustar esto.
    // die('Acceso denegado.');
}

ini_set('display_errors', 1);
error_reporting(E_ALL);

function cargarEnv($filePath)
{
    if (!file_exists($filePath)) {
        return;
    }
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) {
            continue;
        }
        if (strpos($line, '=') !== false) {
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
}

// Cargar variables de entorno (.env en la raíz del proyecto)
cargarEnv(__DIR__ . '/.env');


require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

echo "[" . date('Y-m-d H:i:s') . "] Iniciando sincronización automática de logs de firewalls...\n";

try {
    $db = new Database();
    $pdo = $db->getConnection();

    // 1. Obtener todos los firewalls que se encuentren activos
    $stmt = $pdo->query("SELECT id, nombre, tipo, ip FROM firewalls WHERE activo = 1");
    $firewalls = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($firewalls)) {
        echo "[" . date('Y-m-d H:i:s') . "] No se encontraron firewalls activos para sincronizar.\n";
        exit;
    }

    foreach ($firewalls as $fw) {
        $id = (int) $fw['id'];
        $nombre = $fw['nombre'];
        $tipo = strtolower($fw['tipo']);
        $ip = $fw['ip'];

        echo "--------------------------------------------------\n";
        echo "Procesando Firewall: {$nombre} ({$ip}) [{$tipo}]...\n";

        try {
            // Seleccionar el importador adecuado
            if ($tipo === 'pfsense') {
                $importador = new PfSenseLogImporter($pdo, $id);
            } else {
                $importador = new OpnsenseLogImporter($pdo, $id);
            }

            $resultado = $importador->import(1000);
            echo "  -> Éxito: Procesados: {$resultado['procesados']} | Insertados: {$resultado['insertados']}\n";

            // Ejecutar análisis de seguridad y detección de amenazas
            $alertEngine = new \Firewall\AlertEngine($pdo);
            $alertRes = $alertEngine->procesarAlertas($id);
            if ($alertRes['alertas_creadas'] > 0) {
                echo "  -> ¡ALERTAS DETECTADAS!: Se generaron {$alertRes['alertas_creadas']} nuevas alertas de seguridad.\n";
            }

        } catch (Throwable $e) {
            echo "  -> ERROR en firewall '{$nombre}': " . $e->getMessage() . "\n";
            error_log("Cron Importación Firewall [ID {$id}]: " . $e->getMessage());
        }
    }

    echo "--------------------------------------------------\n";
    echo "[" . date('Y-m-d H:i:s') . "] Sincronización automática finalizada con éxito.\n";

} catch (Throwable $e) {
    echo "ERROR CRÍTICO EN CRON: " . $e->getMessage() . "\n";
    error_log("Error crítico en cron_importar_logs.php: " . $e->getMessage());
}