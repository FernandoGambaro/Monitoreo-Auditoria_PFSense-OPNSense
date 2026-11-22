<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set("America/Montevideo");

function cargarEnvLocal($filePath)
{
    if (!file_exists($filePath))
        return;
    foreach (file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0 || strpos($line, '=') === false)
            continue;
        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
            putenv("$name=$value");
            $_ENV[$name] = $value;
            $_SERVER[$name] = $value;
        }
    }
}
cargarEnvLocal(__DIR__ . '/.env');

require_once __DIR__ . '/bootstrap.php';
use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// -------------------------------------------------------------------------
// ENDPOINT AJAX 1: Paginación Server-Side para Destinos Externos No Validados
// -------------------------------------------------------------------------
if (isset($_GET['ajax_listar_pendientes'])) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    if (ob_get_level()) ob_clean();
    header('Content-Type: application/json; charset=utf-8');

    $draw        = (int) ($_GET['draw'] ?? 1);
    $start       = max(0, (int) ($_GET['start'] ?? 0));
    $length      = min(100, max(10, (int) ($_GET['length'] ?? 25)));
    $searchValue = trim($_GET['search']['value'] ?? '');

    $fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
    $fechaFin    = $_GET['fecha_fin'] ?? date('Y-m-d');
    $sqlInicio   = $fechaInicio . ' 00:00:00';
    $sqlFin      = $fechaFin . ' 23:59:59';

    $orderColIdx = (int) ($_GET['order'][0]['column'] ?? 4);
    $orderDir    = (strtoupper($_GET['order'][0]['dir'] ?? 'DESC') === 'ASC') ? 'ASC' : 'DESC';
    $columnasOrden = [
        0 => 'agg.ip_interna',
        1 => 'agg.ip_externa',
        2 => 'i.pais',
        3 => 'agg.puertos',
        4 => 'agg.total_conexiones'
    ];
    $orderBy = $columnasOrden[$orderColIdx] ?? 'agg.total_conexiones';

    $baseSubquery = "
        SELECT 
            f.ip_origen AS ip_interna,
            f.ip_destino AS ip_externa,
            GROUP_CONCAT(DISTINCT f.puerto_destino ORDER BY f.puerto_destino SEPARATOR ', ') AS puertos,
            COUNT(*) AS total_conexiones
        FROM firewall_eventos f
        WHERE (f.accion = 'PASS' OR f.accion = 'pass')
          AND f.fecha_evento BETWEEN ? AND ?
          AND (f.ip_origen LIKE '192.168.%' OR f.ip_origen LIKE '10.%' OR f.ip_origen LIKE '172.16.%')
          AND f.ip_destino NOT LIKE '192.168.%'
          AND f.ip_destino NOT LIKE '10.%'
          AND f.ip_destino NOT LIKE '172.16.%'
          AND f.ip_destino NOT LIKE '224.%'
          AND f.ip_destino != '255.255.255.255'
        GROUP BY f.ip_origen, f.ip_destino
    ";

    try {
        // Total sin búsqueda
        $sqlTotal = "
            SELECT COUNT(*) 
            FROM ({$baseSubquery}) agg
            LEFT JOIN ips_externas_confiables c ON agg.ip_externa = c.ip COLLATE utf8mb4_unicode_ci
            WHERE c.id IS NULL
        ";
        $stmtTotal = $pdo->prepare($sqlTotal);
        $stmtTotal->execute([$sqlInicio, $sqlFin]);
        $recordsTotal = (int) $stmtTotal->fetchColumn();

        // Filtro de búsqueda opcional
        $whereSearch = "WHERE c.id IS NULL";
        $params = [$sqlInicio, $sqlFin];
        if ($searchValue !== '') {
            $whereSearch .= " AND (agg.ip_interna LIKE ? OR agg.ip_externa LIKE ? OR i.pais LIKE ? OR agg.puertos LIKE ?)";
            $like = '%' . $searchValue . '%';
            array_push($params, $like, $like, $like, $like);
        }

        // Total filtrado
        $sqlFiltered = "
            SELECT COUNT(*)
            FROM ({$baseSubquery}) agg
            LEFT JOIN ips_externas_confiables c ON agg.ip_externa = c.ip COLLATE utf8mb4_unicode_ci
            LEFT JOIN ips i ON agg.ip_externa = i.ip COLLATE utf8mb4_unicode_ci
            {$whereSearch}
        ";
        $stmtFilt = $pdo->prepare($sqlFiltered);
        $stmtFilt->execute($params);
        $recordsFiltered = (int) $stmtFilt->fetchColumn();

        // Datos paginados
        $sqlData = "
            SELECT 
                agg.ip_interna,
                agg.ip_externa,
                agg.puertos,
                agg.total_conexiones,
                COALESCE(NULLIF(TRIM(i.pais), ''), 'Sin resolver') AS pais
            FROM ({$baseSubquery}) agg
            LEFT JOIN ips_externas_confiables c ON agg.ip_externa = c.ip COLLATE utf8mb4_unicode_ci
            LEFT JOIN ips i ON agg.ip_externa = i.ip COLLATE utf8mb4_unicode_ci
            {$whereSearch}
            ORDER BY {$orderBy} {$orderDir}
            LIMIT {$start}, {$length}
        ";
        $stmtData = $pdo->prepare($sqlData);
        $stmtData->execute($params);
        $filas = $stmtData->fetchAll(PDO::FETCH_ASSOC);

        $data = [];
        foreach ($filas as $row) {
            $ipInt = htmlspecialchars($row['ip_interna']);
            $ipExt = htmlspecialchars($row['ip_externa']);
            $pais  = htmlspecialchars($row['pais']);
            $puertos = htmlspecialchars($row['puertos'] ?? '');

            $colInterna = '<span class="badge bg-secondary">' . $ipInt . '</span>';
            $colExterna = '<code><a href="https://www.virustotal.com/gui/ip-address/' . $ipExt . '" target="_blank" class="text-decoration-none fw-bold" title="Analizar en VirusTotal">' . $ipExt . ' <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i></a></code>'
                        . '<a href="https://www.abuseipdb.com/check/' . $ipExt . '" target="_blank" class="ms-2 badge bg-light text-primary border text-decoration-none" title="Verificar en AbuseIPDB">AbuseIPDB</a>';
            $colPuertos = '<small class="text-muted">' . $puertos . '</small>';
            $colConex   = number_format((int) $row['total_conexiones']);
            $colIa      = '<span class="badge bg-light text-muted border">Sin evaluar</span>';
            $colAccion  = '<div class="text-end text-nowrap">'
                        . '<button type="button" class="btn btn-sm btn-outline-primary btn-evaluar-ia me-1" data-ip="' . $ipExt . '" data-puertos="' . $puertos . '" title="Evaluar con IA"><i class="bi bi-cpu"></i> IA</button>'
                        . '<button type="button" class="btn btn-sm btn-outline-success btn-aprobar" data-ip="' . $ipExt . '" data-pais="' . $pais . '"><i class="bi bi-check-circle me-1"></i> Marcar Confiable</button>'
                        . '</div>';

            $data[] = [
                'DT_RowAttr' => ['data-row-ip' => $ipExt],
                0 => $colInterna,
                1 => $colExterna,
                2 => $pais,
                3 => $colPuertos,
                4 => $colConex,
                5 => $colIa,
                6 => $colAccion
            ];
        }

        echo json_encode([
            'draw'            => $draw,
            'recordsTotal'    => $recordsTotal,
            'recordsFiltered' => $recordsFiltered,
            'data'            => $data
        ]);
    } catch (Exception $e) {
        echo json_encode([
            'draw'            => $draw,
            'recordsTotal'    => 0,
            'recordsFiltered' => 0,
            'data'            => [],
            'error'           => $e->getMessage()
        ]);
    }
    exit;
}

function consultarGeminiJson(string $prompt, string $apiKey, string $modelo): array {
    $url = "https://generativelanguage.googleapis.com/v1beta/models/" . rawurlencode($modelo) . ":generateContent?key=" . rawurlencode($apiKey);
    $payload = json_encode([
        'contents' => [
            ['parts' => [['text' => $prompt]]]
        ],
        'generationConfig' => [
            'responseMimeType' => 'application/json',
            'temperature'      => 0.1
        ]
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
        CURLOPT_CONNECTTIMEOUT => 10,
        CURLOPT_TIMEOUT        => 35
    ]);
    $resp = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($resp === false || $curlErr !== '') {
        throw new Exception("Gemini cURL: " . $curlErr);
    }
    if ($httpCode < 200 || $httpCode >= 300) {
        $errApi = json_decode($resp, true);
        $msgApi = $errApi['error']['message'] ?? substr($resp, 0, 160);
        throw new Exception("Gemini HTTP {$httpCode}: {$msgApi}");
    }

    $jsonResp = json_decode($resp, true);
    $texto = $jsonResp['candidates'][0]['content']['parts'][0]['text'] ?? '';
    $datos = json_decode($texto, true);

    if (!is_array($datos) || !array_key_exists('autorizada', $datos)) {
        throw new Exception("Gemini devolvió JSON inválido");
    }
    $datos['_motor'] = "Gemini ({$modelo})";
    return $datos;
}

function consultarOllamaLocalJson(string $prompt, string $baseUrl, string $modelo, int $timeout = 45): array {
    $url = rtrim($baseUrl, '/') . '/api/generate';
    $payload = json_encode([
        'model'  => $modelo,
        'prompt' => $prompt,
        'stream' => false,
        'format' => 'json',
        'options' => [
            'temperature' => 0.1
        ]
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_IPRESOLVE      => CURL_IPRESOLVE_V4,
        CURLOPT_CONNECTTIMEOUT => 8,
        CURLOPT_TIMEOUT        => $timeout
    ]);
    $resp = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlErr = curl_error($ch);
    curl_close($ch);

    if ($resp === false || $curlErr !== '') {
        throw new Exception("Red Local (Ollama) cURL: " . $curlErr);
    }
    if ($httpCode < 200 || $httpCode >= 300) {
        throw new Exception("Red Local (Ollama) HTTP {$httpCode}: " . substr($resp, 0, 160));
    }

    $jsonResp = json_decode($resp, true);
    $texto = trim((string) ($jsonResp['response'] ?? ''));
    $texto = preg_replace('/^```(?:json)?\s*|\s*```$/i', '', $texto);
    $datos = json_decode($texto, true);

    if (!is_array($datos) || !array_key_exists('autorizada', $datos)) {
        throw new Exception("Modelo local devolvió JSON inválido");
    }
    $datos['_motor'] = "Local ({$modelo})";
    return $datos;
}

// -------------------------------------------------------------------------
// ENDPOINT AJAX 2: Valoración de IP Externa (Modelo Local / Gemini)
// -------------------------------------------------------------------------
if (isset($_GET['ajax_evaluar_ia'])) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    while (ob_get_level()) {
        ob_end_clean();
    }
    ini_set('display_errors', 0);
    header('Content-Type: application/json; charset=utf-8');

    $ip = trim($_GET['ip'] ?? '');
    $puertos = trim($_GET['puertos'] ?? '');

    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        echo json_encode(['ok' => false, 'error' => 'Dirección IP inválida']);
        exit;
    }

    $stmtInfo = $pdo->prepare("SELECT pais, abuse_score, reputacion FROM ips WHERE ip = ? LIMIT 1");
    $stmtInfo->execute([$ip]);
    $infoIp = $stmtInfo->fetch(PDO::FETCH_ASSOC) ?: [];

    $ptr = @gethostbyaddr($ip);
    if ($ptr === $ip || $ptr === false || $ptr === '') {
        $ptr = 'Sin registro PTR';
    }
    $pais = $infoIp['pais'] ?? 'Desconocido';
    $abuse = (int) ($infoIp['abuse_score'] ?? 0);

    $prompt = "Eres un analista senior de ciberseguridad SOC. Evalúa si la siguiente dirección IP externa a la que se conectó un equipo interno debe ser AUTORIZADA o NO AUTORIZADA:
- IP Destino: {$ip}
- Reverse DNS (PTR): {$ptr}
- País: {$pais}
- Puertos destino utilizados: {$puertos}
- AbuseIPDB Score: {$abuse}/100

Criterios:
- Autorizar (autorizada: true) solo si pertenece claramente a servicios legítimos conocidos (Cloudflare, Google, Microsoft, AWS, Akamai, Ubuntu/Linux repos, bancos/gobierno Uruguay, CDNs legítimos) y tiene bajo riesgo.
- Rechazar (autorizada: false) si es desconocida, residencial sin PTR claro, sospechosa o tiene score de abuso.

Responde ÚNICAMENTE con un objeto JSON válido con estas claves exactas:
{\"autorizada\": true, \"confianza\": 90, \"categoria\": \"Infraestructura / Cloud\", \"propietario\": \"Nombre empresa o servicio\", \"justificacion\": \"Explicación breve en español\"}";

    $proveedorSolicitado = strtolower(trim((string) ($_GET['proveedor'] ?? (getenv('IA_PROVEEDOR_DEFAULT') ?: 'local'))));
    $fallbackActivo      = (getenv('IA_FALLBACK_AUTOMATICO') ?: '1') === '1';

    $localUrl   = trim((string) (getenv('LOCAL_LLM_URL') ?: ''));
    $localModel = trim((string) (getenv('LOCAL_LLM_MODEL') ?: 'deepseek-coder-v2:16b'));
    $localTime  = max(10, (int) (getenv('LOCAL_LLM_TIMEOUT') ?: 45));

    $gemKey   = trim((string) (getenv('GEMINI_API_KEY') ?: ''));
    $gemModel = trim((string) (getenv('GEMINI_MODEL') ?: 'gemini-2.5-flash'));

    $ordenProveedores = ($proveedorSolicitado === 'gemini')
        ? ['gemini', 'local']
        : ['local', 'gemini'];

    if (!$fallbackActivo) {
        $ordenProveedores = [$ordenProveedores[0]];
    }

    $analisis = null;
    $errores  = [];

    foreach ($ordenProveedores as $prov) {
        try {
            if ($prov === 'local') {
                if ($localUrl === '') {
                    throw new Exception("LOCAL_LLM_URL no configurada");
                }
                $analisis = consultarOllamaLocalJson($prompt, $localUrl, $localModel, $localTime);
                break;
            } elseif ($prov === 'gemini') {
                if ($gemKey === '') {
                    throw new Exception("GEMINI_API_KEY no configurada");
                }
                $analisis = consultarGeminiJson($prompt, $gemKey, $gemModel);
                break;
            }
        } catch (Throwable $ex) {
            $errores[] = $ex->getMessage();
        }
    }

    if ($analisis === null) {
        echo json_encode([
            'ok'    => false,
            'error' => implode(' | ', $errores) ?: 'No se pudo completar la evaluación IA'
        ]);
        exit;
    }

    $autorizada    = filter_var($analisis['autorizada'], FILTER_VALIDATE_BOOLEAN);
    $confianza     = (int) ($analisis['confianza'] ?? 0);
    $categoria     = trim((string) ($analisis['categoria'] ?? 'IA Evaluada'));
    $propietario   = trim((string) ($analisis['propietario'] ?? $ptr));
    $justificacion = trim((string) ($analisis['justificacion'] ?? ''));

    if ($autorizada && $abuse <= 25) {
        $stmtUpsert = $pdo->prepare("
            INSERT INTO ips_externas_confiables 
                (ip, descripcion, categoria, origen_validacion, confianza_ia, justificacion_ia, ultima_revision, notificada_reporte)
            VALUES (?, ?, ?, 'IA', ?, ?, NOW(), 0)
            ON DUPLICATE KEY UPDATE
                descripcion = VALUES(descripcion),
                categoria = VALUES(categoria),
                origen_validacion = 'IA',
                confianza_ia = VALUES(confianza_ia),
                justificacion_ia = VALUES(justificacion_ia),
                ultima_revision = NOW()
        ");
        $stmtUpsert->execute([$ip, $propietario, $categoria, $confianza, $justificacion]);
    } else {
        $autorizada = false;
    }

    echo json_encode([
        'ok'            => true,
        'autorizada'    => $autorizada,
        'confianza'     => $confianza,
        'categoria'     => $categoria,
        'propietario'   => $propietario,
        'justificacion' => $justificacion,
        'ptr'           => $ptr,
        '_motor'        => $analisis['_motor'] ?? ''
    ]);
    exit;
}

// -------------------------------------------------------------------------
// PROCESAR ACCIONES POST MANUALES
// -------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $accion = $_POST['accion'] ?? '';

    if ($accion === 'aprobar_ip') {
        $ip = trim($_POST['ip'] ?? '');
        $desc = trim($_POST['descripcion'] ?? '');
        $cat = trim($_POST['categoria'] ?? 'General');

        if (!empty($ip)) {
            $stmt = $pdo->prepare("
                INSERT INTO ips_externas_confiables (ip, descripcion, categoria, origen_validacion, ultima_revision, notificada_reporte)
                VALUES (?, ?, ?, 'MANUAL', NOW(), 0)
                ON DUPLICATE KEY UPDATE 
                    descripcion = VALUES(descripcion),
                    categoria = VALUES(categoria),
                    origen_validacion = 'MANUAL',
                    ultima_revision = NOW()
            ");
            $stmt->execute([$ip, $desc, $cat]);
            $_SESSION['msg_texto'] = "IP externa {$ip} agregada a la lista de confiables.";
            $_SESSION['msg_tipo'] = "success";
        }
    }

    if ($accion === 'revocar_ip') {
        $id = (int) ($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare("DELETE FROM ips_externas_confiables WHERE id = ?");
            $stmt->execute([$id]);
            $_SESSION['msg_texto'] = "IP eliminada de la lista confiable. Volverá a ser auditada.";
            $_SESSION['msg_tipo'] = "warning";
        }
    }

    if ($accion === 'recaracterizar_ip') {
        $id = (int) ($_POST['id'] ?? 0);
        if ($id > 0) {
            $stmt = $pdo->prepare("UPDATE ips_externas_confiables SET ultima_revision = '2000-01-01 00:00:00' WHERE id = ?");
            $stmt->execute([$id]);
            $_SESSION['msg_texto'] = "IP marcada para recaracterización en el próximo ciclo de análisis.";
            $_SESSION['msg_tipo'] = "info";
        }
    }

    header('Location: trafico_saliente.php');
    exit;
}

$mensaje = $_SESSION['msg_texto'] ?? '';
$tipoAlerta = $_SESSION['msg_tipo'] ?? '';
unset($_SESSION['msg_texto'], $_SESSION['msg_tipo']);

$fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
$fechaFin = $_GET['fecha_fin'] ?? date('Y-m-d');

$ipsConfiables = $pdo->query("
    SELECT * FROM ips_externas_confiables 
    ORDER BY fecha_agregada DESC
")->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-4 mb-5">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2 class="mb-0"><i class="bi bi-diagram-3 text-info me-2"></i>Monitoreo de Tráfico Saliente e IPs Confiables</h2>
        <div class="d-flex align-items-center gap-2">
            <select id="selectProveedorIA" class="form-select form-select-sm" style="width: auto;" title="Motor de evaluación IA">
                <option value="local">Red Local (Ollama)</option>
                <option value="gemini">Google Gemini</option>
            </select>
            <button type="button" id="btnEvaluarLoteIA" class="btn btn-primary">
                <i class="bi bi-cpu me-1"></i> Valorar Primeras 10 con IA
            </button>
        </div>
    </div>

    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= htmlspecialchars($tipoAlerta) ?> alert-dismissible fade show">
            <?= htmlspecialchars($mensaje) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <!-- Filtro de fechas -->
    <div class="card mb-4 shadow-sm">
        <div class="card-body py-2">
            <form method="GET" id="formFiltroFechas" class="row g-2 align-items-end">
                <div class="col-md-3">
                    <label class="form-label small mb-1">Fecha Inicio</label>
                    <input type="date" id="fecha_inicio" name="fecha_inicio" class="form-control form-control-sm" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-3">
                    <label class="form-label small mb-1">Fecha Fin</label>
                    <input type="date" id="fecha_fin" name="fecha_fin" class="form-control form-control-sm" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-2">
                    <button type="submit" class="btn btn-sm btn-primary w-100">Filtrar Actividad</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Pestañas de Navegación -->
    <ul class="nav nav-tabs mb-3" id="tabsSaliente" role="tablist">
        <li class="nav-item">
            <button class="nav-link active fw-bold" data-bs-toggle="tab" data-bs-target="#tab-pendientes" type="button">
                Destinos Externos No Validados <span class="badge bg-warning text-dark ms-1" id="badgePendientesCount">...</span>
            </button>
        </li>
        <li class="nav-item">
            <button class="nav-link fw-bold" data-bs-toggle="tab" data-bs-target="#tab-confiables" type="button">
                IPs Externas Confiables (Whitelist) <span class="badge bg-success ms-1"><?= count($ipsConfiables) ?></span>
            </button>
        </li>
    </ul>
    <div class="d-flex align-items-center gap-2">
    <select id="selectProveedorIA" class="form-select form-select-sm" style="width: auto;" title="Motor de evaluación IA">
        <option value="local">Red Local (Ollama)</option>
        <option value="gemini">Google Gemini</option>
    </select>
    <button type="button" id="btnEvaluarLoteIA" class="btn btn-primary">
        <i class="bi bi-cpu me-1"></i> Valorar Primeras 10 con IA
    </button>
</div>

    <div class="tab-content">
        <!-- TAB 1: DESTINOS PENDIENTES (CARGA PAGINADA SERVER-SIDE) -->
        <div class="tab-pane fade show active" id="tab-pendientes">
            <div class="card shadow-sm">
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="tablaPendientes" class="table table-sm table-hover align-middle w-100">
                            <thead class="table-dark">
                                <tr>
                                    <th>Equipo Interno</th>
                                    <th>IP Externa (VirusTotal)</th>
                                    <th>País</th>
                                    <th>Puertos Destino</th>
                                    <th>Conexiones</th>
                                    <th>Valoración IA</th>
                                    <th class="text-end">Acción</th>
                                </tr>
                            </thead>
                            <tbody></tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- TAB 2: LISTADO DE IPS CONFIABLES -->
        <div class="tab-pane fade" id="tab-confiables">
            <div class="card shadow-sm">
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="tablaConfiables" class="table table-sm table-hover align-middle w-100">
                            <thead class="table-dark">
                                <tr>
                                    <th>IP Confiable (VirusTotal)</th>
                                    <th>Categoría</th>
                                    <th>Descripción / Justificación</th>
                                    <th>Origen</th>
                                    <th>Agregada</th>
                                    <th>Última Revisión</th>
                                    <th class="text-end">Gestión</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($ipsConfiables as $conf):
                                    $ipConf = htmlspecialchars($conf['ip']);
                                    ?>
                                    <tr>
                                        <td>
                                            <code>
                                                <a href="https://www.virustotal.com/gui/ip-address/<?= $ipConf ?>" target="_blank" class="text-decoration-none fw-bold" title="Analizar en VirusTotal">
                                                    <?= $ipConf ?> <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i>
                                                </a>
                                            </code>
                                            <a href="https://www.abuseipdb.com/check/<?= $ipConf ?>" target="_blank" class="ms-2 badge bg-light text-primary border text-decoration-none" title="Verificar en AbuseIPDB">
                                                AbuseIPDB
                                            </a>
                                        </td>
                                        <td><span class="badge bg-info text-dark"><?= htmlspecialchars($conf['categoria'] ?? 'General') ?></span></td>
                                        <td>
                                            <?= htmlspecialchars($conf['descripcion'] ?? '') ?>
                                            <?php if (!empty($conf['justificacion_ia'])): ?>
                                                <br><small class="text-muted fst-italic">IA (<?= $conf['confianza_ia'] ?>%): <?= htmlspecialchars($conf['justificacion_ia']) ?></small>
                                            <?php endif; ?>
                                        </td>
                                        <td>
                                            <?php if ($conf['origen_validacion'] === 'IA'): ?>
                                                <span class="badge bg-primary"><i class="bi bi-cpu"></i> IA</span>
                                            <?php else: ?>
                                                <span class="badge bg-secondary"><i class="bi bi-person"></i> Manual</span>
                                            <?php endif; ?>
                                        </td>
                                        <td><small><?= htmlspecialchars($conf['fecha_agregada']) ?></small></td>
                                        <td><small><?= htmlspecialchars($conf['ultima_revision']) ?></small></td>
                                        <td class="text-end">
                                            <form method="POST" class="d-inline">
                                                <input type="hidden" name="accion" value="recaracterizar_ip">
                                                <input type="hidden" name="id" value="<?= $conf['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-warning" title="Forzar recaracterización">
                                                    <i class="bi bi-arrow-repeat"></i>
                                                </button>
                                            </form>
                                            <form method="POST" class="d-inline" onsubmit="return confirm('¿Revocar confianza de esta IP?');">
                                                <input type="hidden" name="accion" value="revocar_ip">
                                                <input type="hidden" name="id" value="<?= $conf['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-danger" title="Eliminar de confiables">
                                                    <i class="bi bi-trash"></i>
                                                </button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Modal para Aprobar IP Manualmente -->
<div class="modal fade" id="modalAprobarIp" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog">
        <form method="POST" class="modal-content">
            <input type="hidden" name="accion" value="aprobar_ip">
            <div class="modal-header bg-success text-white">
                <h5 class="modal-title">Validar IP Externa como Confiable</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body">
                <div class="mb-3">
                    <label class="form-label fw-bold">Dirección IP</label>
                    <input type="text" name="ip" id="inputModalIp" class="form-control" readonly>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-bold">Categoría</label>
                    <select name="categoria" class="form-select">
                        <option value="Infraestructura / Cloud">Infraestructura / Cloud (AWS, Azure, Google)</option>
                        <option value="Actualizaciones SO">Actualizaciones SO (Microsoft, Linux Repos)</option>
                        <option value="Servicios Financieros / Gov">Servicios Financieros / DGI / Bancos</option>
                        <option value="Proveedor / Cliente">Proveedor / Cliente Legítimo</option>
                        <option value="General">General</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label class="form-label fw-bold">Descripción / Propietario</label>
                    <input type="text" name="descripcion" id="inputModalDesc" class="form-control" placeholder="Ej: Servidor DNS Cloudflare, Windows Update, etc." required>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                <button type="submit" class="btn btn-success">Guardar como Confiable</button>
            </div>
        </form>
    </div>
</div>

<!-- Modal Compacto para Mostrar Errores de IA -->
<div class="modal fade" id="modalErrorIA" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
        <div class="modal-content border-danger">
            <div class="modal-header bg-danger text-white py-2">
                <h6 class="modal-title mb-0"><i class="bi bi-exclamation-triangle-fill me-2"></i>Detalle de Error en Evaluación IA</h6>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body">
                <div class="mb-2 small text-muted" id="modalErrorIaIp"></div>
                <pre class="bg-light border rounded p-2 mb-0 small text-danger" style="white-space: pre-wrap; word-break: break-word;" id="modalErrorIaDetalle"></pre>
            </div>
            <div class="modal-footer py-2">
                <button type="button" class="btn btn-sm btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<script>
function escapeHtml(str) {
    return String(str ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function mostrarModalErrorIA(ip, mensajeError) {
    const ipEl = document.getElementById('modalErrorIaIp');
    const detEl = document.getElementById('modalErrorIaDetalle');
    if (ipEl) ipEl.innerHTML = ip ? `IP evaluada: <code>${escapeHtml(ip)}</code>` : '';
    if (detEl) detEl.textContent = mensajeError || 'Error desconocido';

    const modalEl = document.getElementById('modalErrorIA');
    if (modalEl && typeof bootstrap !== 'undefined') {
        bootstrap.Modal.getOrCreateInstance(modalEl).show();
    }
}

document.addEventListener('DOMContentLoaded', function() {
    let tablaPendientesDT = null;

    if (typeof window.jQuery !== 'undefined' && typeof window.jQuery.fn.DataTable !== 'undefined') {
        if (!window.jQuery.fn.DataTable.isDataTable('#tablaPendientes')) {
            tablaPendientesDT = window.jQuery('#tablaPendientes').DataTable({
                processing: true,
                serverSide: true,
                pageLength: 25,
                order: [[4, 'desc']],
                columnDefs: [
                    { orderable: false, targets: [5, 6] }
                ],
                ajax: {
                    url: 'trafico_saliente.php',
                    data: function(d) {
                        d.ajax_listar_pendientes = 1;
                        d.fecha_inicio = document.getElementById('fecha_inicio').value;
                        d.fecha_fin = document.getElementById('fecha_fin').value;
                    }
                },
                drawCallback: function(settings) {
                    if (settings.json && typeof settings.json.recordsTotal !== 'undefined') {
                        document.getElementById('badgePendientesCount').textContent = settings.json.recordsTotal;
                    }
                }
            });
        }

        if (!window.jQuery.fn.DataTable.isDataTable('#tablaConfiables')) {
            window.jQuery('#tablaConfiables').DataTable({ pageLength: 25 });
        }
    }

    document.addEventListener('click', function(e) {
        const badgeErr = e.target.closest('.btn-ver-error-ia');
        if (badgeErr) {
            e.preventDefault();
            mostrarModalErrorIA(
                badgeErr.getAttribute('data-ip') || '',
                badgeErr.getAttribute('data-error') || ''
            );
            return;
        }

        const btnAprobar = e.target.closest('.btn-aprobar');
        if (btnAprobar) {
            e.preventDefault();
            const ip = btnAprobar.getAttribute('data-ip') || '';
            const pais = btnAprobar.getAttribute('data-pais') || '';

            document.getElementById('inputModalIp').value = ip;
            const inputDesc = document.getElementById('inputModalDesc');
            inputDesc.value = '';
            if (pais && pais !== 'Sin resolver') {
                inputDesc.placeholder = `Ej: Servicio externo en ${pais}`;
            }

            const modalEl = document.getElementById('modalAprobarIp');
            bootstrap.Modal.getOrCreateInstance(modalEl).show();
            return;
        }

        const btnIa = e.target.closest('.btn-evaluar-ia');
        if (btnIa) {
            e.preventDefault();
            evaluarFilaConIA(btnIa);
        }
    });

    function setCeldaErrorCompacta(celdaIa, ip, msgError) {
        celdaIa.innerHTML = `
            <button type="button" class="badge bg-danger border-0 btn-ver-error-ia"
                    data-ip="${escapeHtml(ip)}"
                    data-error="${escapeHtml(msgError)}"
                    title="Clic para ver el detalle del error">
                <i class="bi bi-exclamation-circle me-1"></i>Error IA
            </button>
        `;
    }

    async function evaluarFilaConIA(btn) {
        const ip = btn.getAttribute('data-ip');
        const puertos = btn.getAttribute('data-puertos') || '';
        const proveedor = document.getElementById('selectProveedorIA')?.value || 'local';
        
        const fila = btn.closest('tr');
        const celdaIa = fila.cells[5];

        btn.disabled = true;
        celdaIa.innerHTML = '<span class="spinner-border spinner-border-sm text-primary"></span> <small>Analizando...</small>';

        try {
            const resp = await fetch(
                `trafico_saliente.php?ajax_evaluar_ia=1&ip=${encodeURIComponent(ip)}&puertos=${encodeURIComponent(puertos)}&proveedor=${encodeURIComponent(proveedor)}`
            );
            const rawText = await resp.text();
            let data;
            try {
                data = JSON.parse(rawText);
            } catch (parseErr) {
                throw new Error('Respuesta no JSON: ' + rawText.replace(/<[^>]*>/g, ' ').trim().slice(0, 220));
            }

            if (!data.ok) {
                const errMsg = data.error || 'Error IA';
                setCeldaErrorCompacta(celdaIa, ip, errMsg);
                mostrarModalErrorIA(ip, errMsg);
                btn.disabled = false;
                return;
            }

            const motorTag = data._motor ? `<div class="text-muted" style="font-size:10px;">${escapeHtml(data._motor)}</div>` : '';

            if (data.autorizada) {
                celdaIa.innerHTML = `
                    <span class="badge bg-success"><i class="bi bi-check-circle"></i> Autorizada (${escapeHtml(data.confianza)}%)</span>
                    <br><small class="text-success fw-semibold">${escapeHtml(data.propietario)}</small>
                    <br><small class="text-muted">${escapeHtml(data.justificacion)}</small>
                    ${motorTag}
                `;
                const btnManual = fila.querySelector('.btn-aprobar');
                if (btnManual) btnManual.remove();
                btn.remove();
            } else {
                celdaIa.innerHTML = `
                    <span class="badge bg-danger"><i class="bi bi-x-octagon"></i> No Autorizada (${escapeHtml(data.confianza)}%)</span>
                    <br><small class="text-danger fw-semibold">${escapeHtml(data.propietario)}</small>
                    <br><small class="text-muted">${escapeHtml(data.justificacion)}</small>
                    ${motorTag}
                `;
                btn.disabled = false;
            }
        } catch (err) {
            setCeldaErrorCompacta(celdaIa, ip, err.message);
            mostrarModalErrorIA(ip, err.message);
            btn.disabled = false;
        }
    }

    const btnLote = document.getElementById('btnEvaluarLoteIA');
    if (btnLote) {
        btnLote.addEventListener('click', async function() {
            const botones = Array.from(document.querySelectorAll('.btn-evaluar-ia')).slice(0, 10);
            if (botones.length === 0) return;

            btnLote.disabled = true;
            btnLote.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span> Analizando lote...';

            for (const b of botones) {
                await evaluarFilaConIA(b);
            }

            btnLote.disabled = false;
            btnLote.innerHTML = '<i class="bi bi-cpu me-1"></i> Valorar Primeras 10 con IA';
        });
    }
});
</script>

<?php include 'views/footer.php'; ?>