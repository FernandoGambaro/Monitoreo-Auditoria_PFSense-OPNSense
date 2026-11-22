<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set("America/Montevideo");

// Función para cargar el archivo .env si existe en la raíz del proyecto
function cargarEnv($filePath) {
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

// Cargar el archivo centralizador de la raíz
require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// -------------------------------------------------------------------------
// PETICIÓN AJAX 1: Detalle de intentos bloqueados por PAÍS
// -------------------------------------------------------------------------
if (isset($_GET['ajax_detalle'])) {
    if (ob_get_level()) {
        ob_clean();
    }

    $pais = $_GET['pais'] ?? '';
    $fInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
    $fFin = $_GET['fecha_fin'] ?? date('Y-m-d');
    
    $sqlInicio = $fInicio . ' 00:00:00';
    $sqlFin    = $fFin . ' 23:59:59';
    
    try {
        $stmt = $pdo->prepare("
            SELECT f.fecha_evento, f.ip_origen, f.puerto_origen, f.puerto_destino, f.accion, f.protocolo, i.reputacion
            FROM firewall_eventos f
            JOIN ips i ON f.ip_origen = i.ip
            WHERE (f.accion = 'block' OR f.accion = 'BLOCK')
              AND f.ip_origen NOT LIKE '192.168.1.%'
              AND i.pais = ? 
              AND f.fecha_evento BETWEEN ? AND ?
            ORDER BY f.fecha_evento DESC
        ");
        $stmt->execute([$pais, $sqlInicio, $sqlFin]);
        $detalles = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        echo '<div class="alert alert-danger">Error en base de datos: ' . htmlspecialchars($e->getMessage()) . '</div>';
        exit;
    }
    
    $peticionesRealizadas = 0;
    $limitePorMinuto = 3; 

    echo '<div class="table-responsive"><table class="table table-striped table-bordered table-sm align-middle">';
    echo '<thead class="table-dark"><tr><th>Fecha / Hora</th><th>IP Origen (VirusTotal)</th><th>Reputación</th><th>Puerto Origen</th><th>Puerto Destino</th><th>Protocolo</th></tr></thead><tbody>';
    
    if (empty($detalles)) {
        echo '<tr><td colspan="6" class="text-center text-muted py-3">No se encontraron registros detallados para este país en el rango seleccionado.</td></tr>';
    } else {
        $reputacionEnMemoria = [];

        foreach ($detalles as $row) {
            $ipActual = $row['ip_origen'];
            
            if (isset($reputacionEnMemoria[$ipActual])) {
                $row['reputacion'] = $reputacionEnMemoria[$ipActual];
            } else {
                $stmtIpCheck = $pdo->prepare("SELECT reputacion FROM ips WHERE ip = ?");
                $stmtIpCheck->execute([$ipActual]);
                $estadoDb = $stmtIpCheck->fetchColumn();
                
                $reputacionActual = strtolower(trim($estadoDb ?? ''));
                $esDesconocida = ($reputacionActual === '' || $reputacionActual === 'desconocida' || $reputacionActual === 'n/a' || $reputacionActual === 'desconocido' || $reputacionActual === 'null');
                
                if ($esDesconocida && $peticionesRealizadas < $limitePorMinuto) {
                    $nuevaRep = consultarYGuardarVirusTotal($ipActual, $pdo);
                    
                    if ($nuevaRep !== false) {
                        $row['reputacion'] = $nuevaRep; 
                    } else {
                        $row['reputacion'] = 'DESCONOCIDA';
                    }
                    
                    $peticionesRealizadas++;
                    if ($peticionesRealizadas < $limitePorMinuto) {
                        sleep(1);
                    }
                } else {
                    $row['reputacion'] = (!$esDesconocida) ? $estadoDb : 'DESCONOCIDA';
                }
                
                $reputacionEnMemoria[$ipActual] = $row['reputacion'];
            }

            $repVal = trim($row['reputacion']);
            $rep = strtoupper($repVal);
            
            if ($rep === 'MALA' || $rep === 'MALICIOSA' || $rep === 'BAJA') {
                $badgeRep = '<span class="badge bg-danger">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'MEDIA' || $rep === 'SOSPECHOSA') {
                $badgeRep = '<span class="badge bg-warning text-dark">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'BUENA' || $rep === 'ALTA') {
                $badgeRep = '<span class="badge bg-success">' . htmlspecialchars($repVal) . '</span>';
            } else {
                $badgeRep = '<span class="badge bg-secondary">' . htmlspecialchars($repVal) . '</span>';
            }

            $puertoDest = (int)($row['puerto_destino'] ?? 0);
            $badgePuerto = '<span class="badge bg-secondary">' . $puertoDest . '</span>';
            switch ($puertoDest) {
                case 21:  $badgePuerto = '<span class="badge bg-info text-dark">21 (FTP)</span>'; break;
                case 22:  $badgePuerto = '<span class="badge bg-danger">22 (SSH)</span>'; break;
                case 53:  $badgePuerto = '<span class="badge bg-primary">53 (DNS)</span>'; break;
                case 80:  $badgePuerto = '<span class="badge bg-success">80 (HTTP)</span>'; break;
                case 443: $badgePuerto = '<span class="badge bg-success">443 (HTTPS)</span>'; break;
                case 3306: $badgePuerto = '<span class="badge bg-warning text-dark">3306 (MySQL)</span>'; break;
                case 3389: $badgePuerto = '<span class="badge bg-danger">3389 (RDP)</span>'; break;
            }

            $ipOrigen = htmlspecialchars($ipActual);
            $enlaceIp = '<a href="https://www.virustotal.com/gui/ip-address/' . $ipOrigen . '" target="_blank" class="text-decoration-none fw-bold" title="Ver en VirusTotal">' . $ipOrigen . ' <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i></a>';

            echo '<tr>
                <td>' . htmlspecialchars($row['fecha_evento']) . '</td>
                <td><code>' . $enlaceIp . '</code></td>
                <td>' . $badgeRep . '</td>
                <td>' . htmlspecialchars($row['puerto_origen'] ?? 'N/A') . '</td>
                <td>' . $badgePuerto . '</td>
                <td>' . strtoupper(htmlspecialchars($row['protocolo'])) . '</td>
            </tr>';
        }
    }
    echo '</tbody></table></div>';
    exit; 
}

// -------------------------------------------------------------------------
// PETICIÓN AJAX 2: Detalle de eventos bloqueados para un PUERTO Específico
// -------------------------------------------------------------------------
if (isset($_GET['ajax_detalle_puerto'])) {
    if (ob_get_level()) ob_clean();

    $puerto = (int) ($_GET['puerto'] ?? 0);
    $fInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
    $fFin = $_GET['fecha_fin'] ?? date('Y-m-d');
    
    $sqlInicio = $fInicio . ' 00:00:00';
    $sqlFin    = $fFin . ' 23:59:59';
    
    try {
        $stmt = $pdo->prepare("
            SELECT f.fecha_evento, f.ip_origen, f.ip_destino, f.puerto_origen, f.puerto_destino, f.accion, f.protocolo, i.pais, i.reputacion
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip
            WHERE (f.accion = 'BLOCK' OR f.accion = 'block')
              AND f.puerto_destino = ?
              AND f.fecha_evento BETWEEN ? AND ?
            ORDER BY f.fecha_evento DESC
            LIMIT 500
        ");
        $stmt->execute([$puerto, $sqlInicio, $sqlFin]);
        $detalles = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        echo '<div class="alert alert-danger">Error en base de datos: ' . htmlspecialchars($e->getMessage()) . '</div>';
        exit;
    }

    echo '<div class="d-flex justify-content-between align-items-center mb-3">';
    echo '  <h6 class="mb-0">Registros para el puerto <strong>' . $puerto . '</strong> (' . count($detalles) . ' eventos encontrados)</h6>';
    echo '  <button class="btn btn-sm btn-outline-primary" onclick="exportarDetallePuertoWord(' . $puerto . ')"><i class="bi bi-file-earmark-word me-1"></i> Exportar este Puerto a Word</button>';
    echo '</div>';

    echo '<div class="table-responsive"><table class="table table-striped table-bordered table-sm align-middle">';
    echo '<thead class="table-dark"><tr><th>Fecha / Hora</th><th>IP Origen</th><th>País</th><th>Reputación</th><th>Puerto Origen</th><th>Puerto Destino</th><th>Protocolo</th></tr></thead><tbody>';
    
    if (empty($detalles)) {
        echo '<tr><td colspan="7" class="text-center text-muted py-3">No se encontraron eventos bloqueados para este puerto en el rango seleccionado.</td></tr>';
    } else {
        foreach ($detalles as $row) {
            $repVal = trim($row['reputacion'] ?? 'DESCONOCIDA');
            $rep = strtoupper($repVal);
            
            if ($rep === 'MALA' || $rep === 'MALICIOSA' || $rep === 'BAJA') {
                $badgeRep = '<span class="badge bg-danger">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'MEDIA' || $rep === 'SOSPECHOSA') {
                $badgeRep = '<span class="badge bg-warning text-dark">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'BUENA' || $rep === 'ALTA') {
                $badgeRep = '<span class="badge bg-success">' . htmlspecialchars($repVal) . '</span>';
            } else {
                $badgeRep = '<span class="badge bg-secondary">' . htmlspecialchars($repVal) . '</span>';
            }

            $ipOrigen = htmlspecialchars($row['ip_origen']);
            $enlaceIp = '<a href="https://www.virustotal.com/gui/ip-address/' . $ipOrigen . '" target="_blank" class="text-decoration-none fw-bold" title="Ver en VirusTotal">' . $ipOrigen . ' <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i></a>';
            
            $puertoOrig = (int)($row['puerto_origen'] ?? 0);
            $puertoDest = (int)($row['puerto_destino'] ?? 0);

            echo '<tr>
                <td>' . htmlspecialchars($row['fecha_evento']) . '</td>
                <td><code>' . $enlaceIp . '</code></td>
                <td>' . htmlspecialchars($row['pais'] ?? 'Desconocido') . '</td>
                <td>' . $badgeRep . '</td>
                <td><span class="badge bg-light text-dark border">' . $puertoOrig . '</span></td>
                <td><span class="badge bg-secondary">' . $puertoDest . '</span></td>
                <td>' . strtoupper(htmlspecialchars($row['protocolo'])) . '</td>
            </tr>';
        }
    }
    echo '</tbody></table></div>';
    exit;
}

// -------------------------------------------------------------------------
// PETICIÓN AJAX 3: Detalle de IPs bloqueadas en PUERTO BAJO VIGILANCIA
// -------------------------------------------------------------------------
if (isset($_GET['ajax_detalle_vigilado'])) {
    if (ob_get_level()) ob_clean();

    $puerto  = (int) ($_GET['puerto'] ?? 0);
    $fInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
    $fFin    = $_GET['fecha_fin'] ?? date('Y-m-d');

    $sqlInicio = $fInicio . ' 00:00:00';
    $sqlFin    = $fFin . ' 23:59:59';

    try {
        $stmt = $pdo->prepare("
            SELECT 
                f.ip_origen,
                COUNT(*) AS intentos,
                MIN(f.fecha_evento) AS primer_intento,
                MAX(f.fecha_evento) AS ultimo_intento,
                GROUP_CONCAT(DISTINCT UPPER(f.protocolo) SEPARATOR ', ') AS protocolos,
                i.pais,
                i.reputacion,
                COALESCE(i.abuse_score, 0) AS abuse_score
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
            WHERE (f.accion = 'BLOCK' OR f.accion = 'block')
              AND f.puerto_destino = ?
              AND f.fecha_evento BETWEEN ? AND ?
              AND f.ip_origen NOT LIKE '192.168.%'
              AND f.ip_origen NOT LIKE '10.%'
              AND f.ip_origen NOT LIKE '172.16.%'
            GROUP BY f.ip_origen
            ORDER BY intentos DESC
            LIMIT 300
        ");
        $stmt->execute([$puerto, $sqlInicio, $sqlFin]);
        $ipsBloqueadas = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } catch (Exception $e) {
        echo '<div class="alert alert-danger">Error en base de datos: ' . htmlspecialchars($e->getMessage()) . '</div>';
        exit;
    }

    if (empty($ipsBloqueadas)) {
        echo '<div class="alert alert-info mb-0">No se registraron IPs bloqueadas en este puerto durante el rango seleccionado.</div>';
        exit;
    }

    echo '<div class="table-responsive"><table class="table table-sm table-striped table-hover align-middle mb-0">';
    echo '<thead class="table-dark"><tr>
            <th>IP Origen</th>
            <th>País</th>
            <th>Intentos</th>
            <th>Último Intento</th>
            <th>Protocolo</th>
            <th>Abuse Score</th>
            <th>Reputación</th>
            <th class="text-end">Análisis Externo</th>
          </tr></thead><tbody>';

    foreach ($ipsBloqueadas as $row) {
        $ipOrig = htmlspecialchars($row['ip_origen']);
        $repVal = trim($row['reputacion'] ?? 'DESCONOCIDA');
        if ($repVal === '') $repVal = 'DESCONOCIDA';
        $rep = strtoupper($repVal);

        if ($rep === 'MALA' || $rep === 'MALICIOSA' || $rep === 'BAJA') {
            $badgeRep = '<span class="badge bg-danger">' . htmlspecialchars($repVal) . '</span>';
        } elseif ($rep === 'MEDIA' || $rep === 'SOSPECHOSA') {
            $badgeRep = '<span class="badge bg-warning text-dark">' . htmlspecialchars($repVal) . '</span>';
        } elseif ($rep === 'BUENA' || $rep === 'ALTA') {
            $badgeRep = '<span class="badge bg-success">' . htmlspecialchars($repVal) . '</span>';
        } else {
            $badgeRep = '<span class="badge bg-secondary">' . htmlspecialchars($repVal) . '</span>';
        }

        $score = (int) $row['abuse_score'];
        $badgeScore = ($score >= 50) ? 'bg-danger' : (($score > 0) ? 'bg-warning text-dark' : 'bg-light text-dark border');

        echo '<tr>
            <td><code class="fw-bold">' . $ipOrig . '</code></td>
            <td>' . htmlspecialchars($row['pais'] ?? 'Desconocido') . '</td>
            <td><span class="badge bg-dark">' . number_format($row['intentos']) . '</span></td>
            <td><small>' . htmlspecialchars($row['ultimo_intento']) . '</small></td>
            <td><small>' . htmlspecialchars($row['protocolos']) . '</small></td>
            <td><span class="badge ' . $badgeScore . '">' . $score . '%</span></td>
            <td>' . $badgeRep . '</td>
            <td class="text-end text-nowrap">
                <a href="https://www.virustotal.com/gui/ip-address/' . $ipOrig . '" target="_blank" class="btn btn-sm btn-outline-danger py-0 px-2" title="Analizar en VirusTotal">
                    VirusTotal <i class="bi bi-box-arrow-up-right" style="font-size: 10px;"></i>
                </a>
                <a href="https://www.abuseipdb.com/check/' . $ipOrig . '" target="_blank" class="btn btn-sm btn-outline-primary py-0 px-2 ms-1" title="Verificar en AbuseIPDB">
                    AbuseIPDB <i class="bi bi-box-arrow-up-right" style="font-size: 10px;"></i>
                </a>
            </td>
        </tr>';
    }
    echo '</tbody></table></div>';
    exit;
}

// -------------------------------------------------------------------------
// PETICIÓN AJAX 4: Consultar alertas sin leer (Polling) y marcación
// -------------------------------------------------------------------------
if (isset($_GET['ajax_check_alertas'])) {
    if (ob_get_level()) ob_clean();
    header('Content-Type: application/json');

    $stmt = $pdo->query("
        SELECT a.*, f.nombre as firewall_nombre 
        FROM firewall_alertas a
        JOIN firewalls f ON a.firewall_id = f.id
        WHERE a.leida = 0 
        ORDER BY a.fecha_alerta DESC 
        LIMIT 5
    ");
    $alertas = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['status' => 'success', 'alertas' => $alertas]);
    exit;
}

if (isset($_POST['ajax_marcar_alerta_leida'])) {
    if (ob_get_level()) ob_clean();
    header('Content-Type: application/json');
    $alertaId = (int)($_POST['alerta_id'] ?? 0);
    
    if ($alertaId > 0) {
        $stmt = $pdo->prepare("UPDATE firewall_alertas SET leida = 1 WHERE id = ?");
        $stmt->execute([$alertaId]);
    }
    echo json_encode(['status' => 'ok']);
    exit;
}

// Función auxiliar VirusTotal
function consultarYGuardarVirusTotal($ip, $pdo) {
    $apiKey = getenv('VIRUSTOTAL_API_KEY');
    if (!$apiKey) {
        return false; 
    }
    $url = "https://www.virustotal.com/api/v3/ip_addresses/" . $ip;
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ["x-apikey: " . $apiKey]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if ($httpCode === 200) {
        $data = json_decode($response, true);
        $stats = $data['data']['attributes']['last_analysis_stats'] ?? null;
        if ($stats) {
            $maliciosos = $stats['malicious'] ?? 0;
            $sospechosos = $stats['suspicious'] ?? 0;
            $reputacionLocal = 'DESCONOCIDA';
            if ($maliciosos >= 3) {
                $reputacionLocal = 'MALA';
            } elseif ($maliciosos > 0 || $sospechosos > 0) {
                $reputacionLocal = 'SOSPECHOSA';
            } else {
                $reputacionLocal = 'BUENA';
            }
            $stmt = $pdo->prepare("UPDATE ips SET reputacion = ? WHERE ip = ?");
            $stmt->execute([$reputacionLocal, $ip]);
            return $reputacionLocal;
        }
    }
    return false;
}

// 1. Obtener filtros globales (fechas y límites independientes)
$hoy = date('Y-m-d');
$fechaInicio = $_GET['fecha_inicio'] ?? $hoy;
$fechaFin    = $_GET['fecha_fin'] ?? $hoy;
$limitePais  = $_GET['limite_pais'] ?? '10';
$limitePuerto = $_GET['limite_puerto'] ?? '10';

$sqlInicio = $fechaInicio . ' 00:00:00';
$sqlFin    = $fechaFin . ' 23:59:59';

// 2. Consultas de tarjetas de resumen
$stmtEventos = $pdo->prepare("SELECT COUNT(*) FROM firewall_eventos WHERE fecha_evento BETWEEN ? AND ?");
$stmtEventos->execute([$sqlInicio, $sqlFin]);
$totalEventos = $stmtEventos->fetchColumn();

$stmtIps = $pdo->prepare("SELECT COUNT(DISTINCT ip_origen) FROM firewall_eventos WHERE fecha_evento BETWEEN ? AND ?");
$stmtIps->execute([$sqlInicio, $sqlFin]);
$totalIps = $stmtIps->fetchColumn();

$stmtPaises = $pdo->prepare("
    SELECT COUNT(DISTINCT i.pais) 
    FROM firewall_eventos f
    JOIN ips i ON f.ip_origen = i.ip
    WHERE f.fecha_evento BETWEEN ? AND ?
");
$stmtPaises->execute([$sqlInicio, $sqlFin]);
$totalPaises = $stmtPaises->fetchColumn();

// 2.5 Consulta de Bloqueos en Puertos Bajo Vigilancia (configuracion_puertos_delicados)
$puertosVigiladosResumen = [];
try {
    $stmtVigilados = $pdo->prepare("
        SELECT 
            pd.puerto,
            pd.descripcion,
            COUNT(f.id) AS total_bloqueos,
            COUNT(DISTINCT f.ip_origen) AS ips_unicas,
            MAX(f.fecha_evento) AS ultimo_evento
        FROM configuracion_puertos_delicados pd
        LEFT JOIN firewall_eventos f 
            ON f.puerto_destino = pd.puerto
            AND (f.accion = 'BLOCK' OR f.accion = 'block')
            AND f.fecha_evento BETWEEN ? AND ?
            AND f.ip_origen NOT LIKE '192.168.%'
            AND f.ip_origen NOT LIKE '10.%'
            AND f.ip_origen NOT LIKE '172.16.%'
        WHERE pd.activo = 1
        GROUP BY pd.puerto, pd.descripcion
        ORDER BY total_bloqueos DESC, pd.puerto ASC
    ");
    $stmtVigilados->execute([$sqlInicio, $sqlFin]);
    $puertosVigiladosResumen = $stmtVigilados->fetchAll(PDO::FETCH_ASSOC);
} catch (Exception $e) {
    // Si la tabla aún no existe, continúa sin interrumpir el dashboard
    $puertosVigiladosResumen = [];
}

// 3. Datos para el Gráfico de Países
$sqlLimitPais = ($limitePais === 'all') ? '' : ' LIMIT 10';
$stmtGraficoPais = $pdo->prepare("
    SELECT i.pais, COUNT(*) as total_bloqueos
    FROM firewall_eventos f
    JOIN ips i ON f.ip_origen = i.ip
    WHERE (f.accion = 'block' OR f.accion = 'BLOCK')
      AND f.fecha_evento BETWEEN ? AND ?
      AND f.ip_origen NOT LIKE '192.168.%'
      AND f.ip_origen NOT LIKE '10.%'
      AND f.ip_origen NOT LIKE '172.16.%'
    GROUP BY i.pais
    ORDER BY total_bloqueos DESC
    {$sqlLimitPais}
");
$stmtGraficoPais->execute([$sqlInicio, $sqlFin]);
$datosPaises = $stmtGraficoPais->fetchAll(PDO::FETCH_ASSOC);

$labelsPaises = [];
$valoresBloqueosPaises = [];
foreach ($datosPaises as $row) {
    $labelsPaises[] = $row['pais'] ?? 'Desconocido';
    $valoresBloqueosPaises[] = (int) $row['total_bloqueos'];
}

// 4. Datos para el Gráfico de Puertos
$sqlLimitPuerto = ($limitePuerto === 'all') ? '' : ' LIMIT 10';
$stmtPuertos = $pdo->prepare("
    SELECT puerto_destino, COUNT(*) as total_bloqueos
    FROM firewall_eventos
    WHERE (accion = 'BLOCK' OR accion = 'block')
      AND fecha_evento BETWEEN ? AND ?
      AND puerto_destino > 0
    GROUP BY puerto_destino
    ORDER BY total_bloqueos DESC
    {$sqlLimitPuerto}
");
$stmtPuertos->execute([$sqlInicio, $sqlFin]);
$datosPuertos = $stmtPuertos->fetchAll(PDO::FETCH_ASSOC);

function obtenerNombrePuerto(int $puerto): string {
    $servicios = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
        80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS', 445 => 'SMB',
        1433 => 'MSSQL', 3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL', 8080 => 'HTTP-Proxy'
    ];
    return isset($servicios[$puerto]) ? "{$puerto} ({$servicios[$puerto]})" : (string) $puerto;
}

$labelsPuertos = [];
$valoresBloqueosPuertos = [];
$puertosRaw = [];

foreach ($datosPuertos as $row) {
    $p = (int) $row['puerto_destino'];
    $puertosRaw[] = $p;
    $labelsPuertos[] = obtenerNombrePuerto($p);
    $valoresBloqueosPuertos[] = (int) $row['total_bloqueos'];
}

// Paletas de colores y alturas dinámicas
$palette = [
    'rgba(13, 110, 253, 0.7)',   // Azul
    'rgba(220, 53, 69, 0.7)',   // Rojo
    'rgba(25, 135, 84, 0.7)',   // Verde
    'rgba(255, 193, 7, 0.7)',   // Amarillo
    'rgba(111, 66, 193, 0.7)',  // Morado
    'rgba(13, 202, 240, 0.7)',  // Cian
    'rgba(253, 126, 20, 0.7)',  // Naranja
    'rgba(232, 62, 140, 0.7)',  // Rosa
    'rgba(108, 117, 125, 0.7)', // Gris
    'rgba(32, 201, 151, 0.7)'   // Turquesa
];

$bgColorsPais = [];
$borderColorsPais = [];
for ($i = 0; $i < count($labelsPaises); $i++) {
    $bgColorsPais[] = $palette[$i % count($palette)];
    $borderColorsPais[] = str_replace('0.7', '1', $palette[$i % count($palette)]);
}

$bgColorsPuerto = [];
$borderColorsPuerto = [];
for ($i = 0; $i < count($labelsPuertos); $i++) {
    $bgColorsPuerto[] = $palette[$i % count($palette)];
    $borderColorsPuerto[] = str_replace('0.7', '1', $palette[$i % count($palette)]);
}

$canvasHeightPais = ($limitePais === 'all') ? max(600, count($labelsPaises) * 38) : 400;
$canvasHeightPuerto = ($limitePuerto === 'all') ? max(600, count($labelsPuertos) * 38) : 400;

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-4 mb-5">

    <!-- Formulario de Filtro por Fechas General -->
    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <form method="GET" id="formFiltro" class="row g-3 align-items-end">
                <input type="hidden" name="limite_pais" value="<?= htmlspecialchars($limitePais) ?>">
                <input type="hidden" name="limite_puerto" value="<?= htmlspecialchars($limitePuerto) ?>">
                <div class="col-md-4">
                    <label for="fecha_inicio" class="form-label">Fecha Inicio</label>
                    <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-4">
                    <label for="fecha_fin" class="form-label">Fecha Fin</label>
                    <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-4">
                    <button type="submit" class="btn btn-primary w-100">Filtrar</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Tarjetas de Estadísticas -->
    <div class="row mb-4 g-3">
        <div class="col-md-4">
            <div class="card text-center shadow-sm">
                <div class="card-body">
                    <h5 class="text-muted">Total Eventos</h5>
                    <h2><?= number_format($totalEventos) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-center shadow-sm">
                <div class="card-body">
                    <h5 class="text-muted">IPs Únicas</h5>
                    <h2><?= number_format($totalIps) ?></h2>
                </div>
            </div>
        </div>
        <div class="col-md-4">
            <div class="card text-center shadow-sm">
                <div class="card-body">
                    <h5 class="text-muted">Países</h5>
                    <h2><?= number_format($totalPaises) ?></h2>
                </div>
            </div>
        </div>
    </div>

    <!-- NUEVA SECCIÓN: Bloqueos en Puertos Bajo Vigilancia -->
    <div class="card shadow-sm mb-4 border-top border-danger border-3">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <span><i class="bi bi-shield-lock-fill text-danger me-2"></i>Bloqueos en Puertos Bajo Vigilancia (Delicados)</span>
            <a href="configuracion_seguridad.php" class="btn btn-sm btn-outline-light">
                <i class="bi bi-sliders me-1"></i> Gestionar Puertos
            </a>
        </div>
        <div class="card-body">
            <?php if (empty($puertosVigiladosResumen)): ?>
                <p class="text-muted mb-0">No hay puertos bajo vigilancia configurados. Puedes agregarlos desde <strong>Configurar Seguridad</strong>.</p>
            <?php else: ?>
                <div class="table-responsive">
                    <table class="table table-sm table-hover align-middle mb-0">
                        <thead class="table-light">
                            <tr>
                                <th>Puerto</th>
                                <th>Servicio / Descripción</th>
                                <th class="text-center">Intentos Bloqueados</th>
                                <th class="text-center">IPs Únicas</th>
                                <th>Último Bloqueo</th>
                                <th class="text-end">Detalle de IPs</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($puertosVigiladosResumen as $pv): 
                                $cantBloqueos = (int) $pv['total_bloqueos'];
                            ?>
                            <tr>
                                <td><span class="badge bg-danger fs-6"><?= (int) $pv['puerto'] ?></span></td>
                                <td class="fw-semibold"><?= htmlspecialchars($pv['descripcion'] ?? 'Sin descripción') ?></td>
                                <td class="text-center">
                                    <span class="badge <?= ($cantBloqueos > 0) ? 'bg-danger' : 'bg-secondary' ?>">
                                        <?= number_format($cantBloqueos) ?>
                                    </span>
                                </td>
                                <td class="text-center"><?= number_format((int) $pv['ips_unicas']) ?></td>
                                <td><small class="text-muted"><?= $pv['ultimo_evento'] ? htmlspecialchars($pv['ultimo_evento']) : 'Sin bloqueos en el rango' ?></small></td>
                                <td class="text-end">
                                    <button type="button" 
                                            class="btn btn-sm <?= ($cantBloqueos > 0) ? 'btn-outline-danger' : 'btn-outline-secondary' ?> btn-ver-vigilado"
                                            data-puerto="<?= (int) $pv['puerto'] ?>"
                                            data-desc="<?= htmlspecialchars($pv['descripcion'] ?? '') ?>"
                                            <?= ($cantBloqueos === 0) ? 'disabled' : '' ?>>
                                        <i class="bi bi-search me-1"></i> Ver IPs Bloqueadas
                                    </button>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <!-- Sección de Gráficos -->
    <div class="row">
        <!-- Gráfico de Intentos Bloqueados por País -->
        <div class="col-lg-12 mb-4">
            <div class="card shadow-sm">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <span>Intentos Bloqueados por País <small class="text-info" style="font-size: 12px;">(Haz clic en una barra para ver detalles)</small></span>
                    <div class="d-flex align-items-center gap-2">
                        <label for="selectLimitePais" class="form-label mb-0 text-white me-2" style="font-size: 14px;">Mostrar:</label>
                        <select id="selectLimitePais" class="form-select form-select-sm" style="width: auto;">
                            <option value="10" <?= ($limitePais === '10') ? 'selected' : '' ?>>Top 10 Países</option>
                            <option value="all" <?= ($limitePais === 'all') ? 'selected' : '' ?>>Todos los Países</option>
                        </select>
                    </div>
                </div>
                <div class="card-body" style="position: relative; height: <?= $canvasHeightPais ?>px; overflow-y: auto;">
                    <canvas id="graficoBloqueosPais"></canvas>
                </div>
            </div>
        </div>

        <!-- Gráfico de Top Puertos Destino Bloqueados -->
        <div class="col-lg-12 mb-4">
            <div class="card shadow-sm">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <span>Top Puertos Destino Bloqueados <small class="text-info" style="font-size: 12px;">(Haz clic en una barra para ver detalles)</small></span>
                    <div class="d-flex align-items-center gap-2">
                        <label for="selectLimitePuerto" class="form-label mb-0 text-white me-2" style="font-size: 14px;">Mostrar:</label>
                        <select id="selectLimitePuerto" class="form-select form-select-sm" style="width: auto;">
                            <option value="10" <?= ($limitePuerto === '10') ? 'selected' : '' ?>>Top 10 Puertos</option>
                            <option value="all" <?= ($limitePuerto === 'all') ? 'selected' : '' ?>>Todos los Puertos</option>
                        </select>
                    </div>
                </div>
                <div class="card-body" style="position: relative; height: <?= $canvasHeightPuerto ?>px; overflow-y: auto;">
                    <canvas id="graficoPuertos"></canvas>
                </div>
            </div>
        </div>
    </div>

</div>

<!-- Modal de Bootstrap para Detalles por País -->
<div class="modal fade" id="modalDetallesPais" tabindex="-1" aria-labelledby="modalLabel" aria-hidden="true">
  <div class="modal-dialog modal-xl modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title" id="modalLabel">Detalle de Intentos Bloqueados</h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body" id="modalBodyContenido">
        <div class="text-center py-4">
          <div class="spinner-border text-primary" role="status"></div>
          <p class="mt-2">Cargando detalles...</p>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<!-- Modal para Detalles del Puerto -->
<div class="modal fade" id="modalDetallesPuerto" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header bg-dark text-white">
                <h5 class="modal-title" id="modalLabelPuerto">Detalle del Puerto</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body" id="modalBodyPuerto">
                <div class="text-center py-4">
                    <div class="spinner-border text-primary" role="status"></div>
                    <p class="mt-2">Cargando eventos del puerto...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<!-- NUEVO MODAL: IPs Bloqueadas en Puerto Bajo Vigilancia -->
<div class="modal fade" id="modalPuertoVigilado" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header bg-danger text-white">
                <h5 class="modal-title" id="modalLabelVigilado">IPs Bloqueadas - Puerto Bajo Vigilancia</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body" id="modalBodyVigilado">
                <div class="text-center py-4">
                    <div class="spinner-border text-danger" role="status"></div>
                    <p class="mt-2">Consultando IPs y reputación...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<!-- Contenedor flotante para los Popups de Alerta en tiempo real -->
<div class="toast-container position-fixed bottom-0 end-0 p-3" style="z-index: 1090;" id="toastContainer"></div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
// Selectores de Límite independientes
document.getElementById('selectLimitePais').addEventListener('change', function() {
    const url = new URL(window.location.href);
    url.searchParams.set('limite_pais', this.value);
    window.location.href = url.toString();
});

document.getElementById('selectLimitePuerto').addEventListener('change', function() {
    const url = new URL(window.location.href);
    url.searchParams.set('limite_puerto', this.value);
    window.location.href = url.toString();
});

// Delegación de evento para abrir modal de Puerto Bajo Vigilancia
document.addEventListener('click', function(e) {
    const btn = e.target.closest('.btn-ver-vigilado');
    if (!btn) return;

    e.preventDefault();
    const puerto = btn.getAttribute('data-puerto');
    const desc   = btn.getAttribute('data-desc');
    const fechaInicio = document.getElementById('fecha_inicio').value;
    const fechaFin    = document.getElementById('fecha_fin').value;

    const modalEl    = document.getElementById('modalPuertoVigilado');
    const modalTitle = document.getElementById('modalLabelVigilado');
    const modalBody  = document.getElementById('modalBodyVigilado');

    modalTitle.textContent = `IPs Bloqueadas en Puerto Vigilado ${puerto}${desc ? ' (' + desc + ')' : ''}`;
    modalBody.innerHTML = `
        <div class="text-center py-4">
            <div class="spinner-border text-danger" role="status"></div>
            <p class="mt-2">Cargando IPs bloqueadas y reputación...</p>
        </div>`;

    bootstrap.Modal.getOrCreateInstance(modalEl).show();

    fetch(`dashboard.php?ajax_detalle_vigilado=1&puerto=${puerto}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`)
        .then(r => r.text())
        .then(html => { modalBody.innerHTML = html; })
        .catch(() => { modalBody.innerHTML = '<div class="alert alert-danger">Error al cargar los datos del servidor.</div>'; });
});

// 1. Inicializar Gráfico de Países
const ctxPais = document.getElementById('graficoBloqueosPais').getContext('2d');
const graficoBloqueosPais = new Chart(ctxPais, {
    type: 'bar',
    data: {
        labels: <?= json_encode($labelsPaises) ?>,
        datasets: [{
            label: 'Intentos Bloqueados',
            data: <?= json_encode($valoresBloqueosPaises) ?>,
            backgroundColor: <?= json_encode($bgColorsPais) ?>,
            borderColor: <?= json_encode($borderColorsPais) ?>,
            borderWidth: 1
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { ticks: { autoSkip: false, font: { size: 12 } } },
            x: { beginAtZero: true, precision: 0 }
        },
        plugins: { legend: { display: false } },
        onClick: function(event, elements) {
            if (elements.length > 0) {
                const index = elements[0].index;
                const pais = this.data.labels[index];
                
                const modalEl = document.getElementById('modalDetallesPais');
                const modalTitle = document.getElementById('modalLabel');
                const modalBody = document.getElementById('modalBodyContenido');
                
                modalTitle.innerText = `Intentos Bloqueados - ${pais}`;
                modalBody.innerHTML = `
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Cargando registros para ${pais}...</p>
                    </div>`;
                
                const bsModal = bootstrap.Modal.getOrCreateInstance(modalEl);
                bsModal.show();
                
                const fechaInicio = document.getElementById('fecha_inicio').value;
                const fechaFin = document.getElementById('fecha_fin').value;
                
                fetch(`dashboard.php?ajax_detalle=1&pais=${encodeURIComponent(pais)}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`)
                    .then(response => response.text())
                    .then(html => { modalBody.innerHTML = html; })
                    .catch(error => { modalBody.innerHTML = `<div class="alert alert-danger">Error al cargar los datos del servidor.</div>`; });
            }
        }
    }
});

// 2. Inicializar Gráfico de Puertos
const puertosRawData = <?= json_encode($puertosRaw) ?>;
const ctxPuerto = document.getElementById('graficoPuertos').getContext('2d');
const graficoPuertos = new Chart(ctxPuerto, {
    type: 'bar',
    data: {
        labels: <?= json_encode($labelsPuertos) ?>,
        datasets: [{
            label: 'Bloqueos por Puerto',
            data: <?= json_encode($valoresBloqueosPuertos) ?>,
            backgroundColor: <?= json_encode($bgColorsPuerto) ?>,
            borderColor: <?= json_encode($borderColorsPuerto) ?>,
            borderWidth: 1
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
            y: { ticks: { autoSkip: false, font: { size: 12 } } },
            x: { beginAtZero: true, precision: 0 }
        },
        plugins: { legend: { display: false } },
        onClick: function(event, elements) {
            if (elements.length > 0) {
                const index = elements[0].index;
                const puertoNum = puertosRawData[index];
                const puertoLabel = this.data.labels[index];
                
                const modalEl = document.getElementById('modalDetallesPuerto');
                const modalTitle = document.getElementById('modalLabelPuerto');
                const modalBody = document.getElementById('modalBodyPuerto');
                
                modalTitle.innerText = `Detalle de Eventos Bloqueados - Puerto ${puertoLabel}`;
                modalBody.innerHTML = `
                    <div class="text-center py-4">
                        <div class="spinner-border text-primary" role="status"></div>
                        <p class="mt-2">Cargando registros para el puerto ${puertoLabel}...</p>
                    </div>`;
                
                const bsModal = bootstrap.Modal.getOrCreateInstance(modalEl);
                bsModal.show();
                
                const fechaInicio = document.getElementById('fecha_inicio').value;
                const fechaFin = document.getElementById('fecha_fin').value;
                
                fetch(`dashboard.php?ajax_detalle_puerto=1&puerto=${puertoNum}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`)
                    .then(response => response.text())
                    .then(html => { modalBody.innerHTML = html; })
                    .catch(error => { modalBody.innerHTML = `<div class="alert alert-danger">Error al cargar datos del servidor.</div>`; });
            }
        }
    }
});

function exportarDetallePuertoWord(puerto) {
    const fechaInicio = document.getElementById('fecha_inicio').value;
    const fechaFin = document.getElementById('fecha_fin').value;
    window.location.href = `generar_word_puertos.php?puerto=${puerto}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`;
}

// Polling de Alertas de Seguridad en Tiempo Real
function verificarAlertasSeguridad() {
    fetch('dashboard.php?ajax_check_alertas=1')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success' && data.alertas.length > 0) {
                const container = document.getElementById('toastContainer');
                
                data.alertas.forEach(alerta => {
                    const toastId = `toast-alerta-${alerta.id}`;
                    if (document.getElementById(toastId)) return;

                    const isCritico = alerta.nivel_riesgo === 'CRITICO';
                    const bgHeader = isCritico ? 'bg-danger text-white' : 'bg-warning text-dark';
                    
                    const toastHtml = `
                        <div id="${toastId}" class="toast shadow-lg" role="alert" aria-live="assertive" aria-atomic="true" data-bs-autohide="false">
                            <div class="toast-header ${bgHeader}">
                                <i class="bi bi-shield-exclamation me-2"></i>
                                <strong class="me-auto">${alerta.tipo_alerta} (${alerta.firewall_nombre})</strong>
                                <small>${alerta.fecha_alerta}</small>
                                <button type="button" class="btn-close ${isCritico ? 'btn-close-white' : ''}" data-bs-dismiss="toast" onclick="marcarAlertaLeida(${alerta.id})"></button>
                            </div>
                            <div class="toast-body bg-white">
                                <p class="mb-2">${alerta.mensaje}</p>
                                ${alerta.ip_origen ? `<a href="https://www.virustotal.com/gui/ip-address/${alerta.ip_origen}" target="_blank" class="btn btn-sm btn-outline-danger py-0" style="font-size:11px;">Ver IP en VirusTotal</a>` : ''}
                                <button class="btn btn-sm btn-link text-secondary float-end p-0" onclick="marcarAlertaLeida(${alerta.id}, '${toastId}')">Descartar</button>
                            </div>
                        </div>
                    `;

                    container.insertAdjacentHTML('beforeend', toastHtml);
                    const toastEl = document.getElementById(toastId);
                    const bsToast = new bootstrap.Toast(toastEl);
                    bsToast.show();
                });
            }
        })
        .catch(err => console.error("Error verificando alertas:", err));
}

function marcarAlertaLeida(id, toastElementId) {
    const formData = new FormData();
    formData.append('ajax_marcar_alerta_leida', '1');
    formData.append('alerta_id', id);

    fetch('dashboard.php', { method: 'POST', body: formData })
        .then(() => {
            if (toastElementId) {
                const el = document.getElementById(toastElementId);
                if (el) el.remove();
            }
        });
}

// Iniciar verificación a los 2 segundos y luego cada 20 segundos
setTimeout(verificarAlertasSeguridad, 2000);
setInterval(verificarAlertasSeguridad, 20000);
</script>

<?php include 'views/footer.php'; ?>