<?php

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Cargar variables de entorno si existe .env
function cargarEnv($filePath)
{
    if (!file_exists($filePath))
        return;
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0)
            continue;
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

cargarEnv(__DIR__ . '/.env');

// Cargar el archivo centralizador de la raíz
require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// -------------------------------------------------------------------------
// PETICIÓN AJAX: Detalle de eventos bloqueados para un Puerto Específico
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
            WHERE f.accion = 'BLOCK' 
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
// VISTA PRINCIPAL DEL REPORTE
// -------------------------------------------------------------------------
$hoy = date('Y-m-d');
$fechaInicio = $_GET['fecha_inicio'] ?? $hoy;
$fechaFin = $_GET['fecha_fin'] ?? $hoy;
$limite = $_GET['limite'] ?? '10';
$ipBusqueda = trim($_GET['ip_busqueda'] ?? '');

$sqlInicio = $fechaInicio . ' 00:00:00';
$sqlFin = $fechaFin . ' 23:59:59';

$sqlLimit = ($limite === 'all') ? '' : ' LIMIT 10';

// Consulta para obtener los puertos destino más bloqueados (Gráfico)
$stmtPuertos = $pdo->prepare("
    SELECT puerto_destino, COUNT(*) as total_bloqueos
    FROM firewall_eventos
    WHERE accion = 'BLOCK'
      AND fecha_evento BETWEEN ? AND ?
      AND puerto_destino > 0
    GROUP BY puerto_destino
    ORDER BY total_bloqueos DESC
    {$sqlLimit}
");
$stmtPuertos->execute([$sqlInicio, $sqlFin]);
$datosPuertos = $stmtPuertos->fetchAll(PDO::FETCH_ASSOC);

// Si se especificó una IP para buscar, consultamos qué puertos intentó acceder y fueron bloqueados
$datosIpBusqueda = [];
if (!empty($ipBusqueda)) {
    $stmtIp = $pdo->prepare("
        SELECT f.fecha_evento, f.ip_origen, f.puerto_origen, f.puerto_destino, f.protocolo, i.pais, i.reputacion
        FROM firewall_eventos f
        LEFT JOIN ips i ON f.ip_origen = i.ip
        WHERE f.accion = 'BLOCK'
          AND f.ip_origen LIKE ?
          AND f.fecha_evento BETWEEN ? AND ?
        ORDER BY f.fecha_evento DESC
        LIMIT 300
    ");
    $stmtIp->execute(['%' . $ipBusqueda . '%', $sqlInicio, $sqlFin]);
    $datosIpBusqueda = $stmtIp->fetchAll(PDO::FETCH_ASSOC);
}

// Mapeo de puertos conocidos para enriquecer las etiquetas del gráfico
function obtenerNombrePuerto(int $puerto): string
{
    $servicios = [
        21 => 'FTP', 22 => 'SSH', 23 => 'Telnet', 25 => 'SMTP', 53 => 'DNS',
        80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS', 445 => 'SMB',
        1433 => 'MSSQL', 3306 => 'MySQL', 3389 => 'RDP', 5432 => 'PostgreSQL', 8080 => 'HTTP-Proxy'
    ];
    return isset($servicios[$puerto]) ? "{$puerto} ({$servicios[$puerto]})" : (string) $puerto;
}

$labelsPuertos = [];
$valoresBloqueos = [];
$puertosRaw = [];

foreach ($datosPuertos as $row) {
    $p = (int) $row['puerto_destino'];
    $puertosRaw[] = $p;
    $labelsPuertos[] = obtenerNombrePuerto($p);
    $valoresBloqueos[] = (int) $row['total_bloqueos'];
}

$palette = [
    'rgba(220, 53, 69, 0.7)',   // Rojo
    'rgba(13, 110, 253, 0.7)',   // Azul
    'rgba(255, 193, 7, 0.7)',   // Amarillo
    'rgba(111, 66, 193, 0.7)',  // Morado
    'rgba(25, 135, 84, 0.7)',   // Verde
    'rgba(253, 126, 20, 0.7)',  // Naranja
    'rgba(13, 202, 240, 0.7)',  // Cian
    'rgba(232, 62, 140, 0.7)',  // Rosa
    'rgba(108, 117, 125, 0.7)'  // Gris
];

$bgColors = [];
$borderColors = [];
$paletteCount = count($palette);

for ($i = 0; $i < count($labelsPuertos); $i++) {
    $bgColors[] = $palette[$i % $paletteCount];
    $borderColors[] = str_replace('0.7', '1', $palette[$i % $paletteCount]);
}

$canvasHeight = max(400, count($labelsPuertos) * 35);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-4 mb-5">

    <div class="d-flex justify-content-between align-items-center mb-3">
        <h3>Reporte de Puertos Más Bloqueados</h3>
        <a href="generar_word_puertos.php?fecha_inicio=<?= urlencode($fechaInicio) ?>&fecha_fin=<?= urlencode($fechaFin) ?>" class="btn btn-success">
            <i class="bi bi-file-word me-1"></i> Descargar Reporte en Word (.docx)
        </a>
    </div>

    <!-- Formulario de Filtros y Búsqueda por IP -->
    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <form method="GET" class="row g-3 align-items-end" id="formFiltro">
                <input type="hidden" name="limite" value="<?= htmlspecialchars($limite) ?>">
                <div class="col-md-3">
                    <label for="fecha_inicio" class="form-label">Fecha Inicio</label>
                    <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-3">
                    <label for="fecha_fin" class="form-label">Fecha Fin</label>
                    <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-3">
                    <label for="ip_busqueda" class="form-label">Buscar por IP Origen</label>
                    <input type="text" class="form-control" id="ip_busqueda" name="ip_busqueda" placeholder="Ej: 190.64 o IP completa" value="<?= htmlspecialchars($ipBusqueda) ?>">
                </div>
                <div class="col-md-3 d-flex gap-2">
                    <button type="submit" class="btn btn-primary w-50">Filtrar</button>
                    <a href="reporte_puertos.php" class="btn btn-secondary w-50" title="Restablecer filtros y búsqueda">Restablecer</a>
                </div>
            </form>
        </div>
    </div>

    <!-- Resultados específicos de la Búsqueda por IP -->
    <?php if (!empty($ipBusqueda)): ?>
    <div class="card shadow-sm mb-4 border-primary">
        <div class="card-header bg-primary text-white d-flex justify-content-between align-items-center">
            <span><i class="bi bi-search me-2"></i> Puertos bloqueados para la IP: <strong><?= htmlspecialchars($ipBusqueda) ?></strong> (<?= count($datosIpBusqueda) ?> intentos encontrados)</span>
            <a href="reporte_puertos.php?fecha_inicio=<?= urlencode($fechaInicio) ?>&fecha_fin=<?= urlencode($fechaFin) ?>&limite=<?= urlencode($limite) ?>" class="btn btn-sm btn-light">Cerrar Búsqueda IP</a>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped table-bordered table-sm align-middle">
                    <thead class="table-dark">
                        <tr>
                            <th>Fecha / Hora</th>
                            <th>IP Origen</th>
                            <th>País</th>
                            <th>Reputación</th>
                            <th>Puerto Origen</th>
                            <th>Puerto Destino Intentado</th>
                            <th>Protocolo</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($datosIpBusqueda)): ?>
                            <tr>
                                <td colspan="7" class="text-center text-muted py-3">No se encontraron intentos bloqueados para la IP "<?= htmlspecialchars($ipBusqueda) ?>" en el rango de fechas seleccionado.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($datosIpBusqueda as $row): 
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

                                $ipOrg = htmlspecialchars($row['ip_origen']);
                                $enlaceIp = '<a href="https://www.virustotal.com/gui/ip-address/' . $ipOrg . '" target="_blank" class="text-decoration-none fw-bold" title="Ver en VirusTotal">' . $ipOrg . ' <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i></a>';
                            ?>
                                <tr>
                                    <td><?= htmlspecialchars($row['fecha_evento']) ?></td>
                                    <td><code><?= $enlaceIp ?></code></td>
                                    <td><?= htmlspecialchars($row['pais'] ?? 'Desconocido') ?></td>
                                    <td><?= $badgeRep ?></td>
                                    <td><span class="badge bg-light text-dark border"><?= (int)$row['puerto_origen'] ?></span></td>
                                    <td><span class="badge bg-danger"><?= (int)$row['puerto_destino'] ?></span></td>
                                    <td><?= strtoupper(htmlspecialchars($row['protocolo'])) ?></td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    <?php endif; ?>

    <!-- Gráfico principal de Puertos Más Bloqueados -->
    <div class="card shadow-sm mb-4">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <span>Top Puertos Destino Bloqueados <small class="text-info">(Haz clic en una barra para ver detalles)</small></span>
            <div class="d-flex align-items-center gap-2">
                <label for="selectLimite" class="form-label mb-0 text-white me-2" style="font-size: 14px;">Mostrar:</label>
                <select id="selectLimite" class="form-select form-select-sm" style="width: auto;">
                    <option value="10" <?= ($limite === '10') ? 'selected' : '' ?>>Top 10 Puertos</option>
                    <option value="all" <?= ($limite === 'all') ? 'selected' : '' ?>>Todos los Puertos</option>
                </select>
            </div>
        </div>
        <div class="card-body" style="position: relative; height: <?= $canvasHeight ?>px;">
            <canvas id="graficoPuertos"></canvas>
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

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<script>
document.getElementById('selectLimite').addEventListener('change', function() {
    const url = new URL(window.location.href);
    url.searchParams.set('limite', this.value);
    window.location.href = url.toString();
});

const puertosRawData = <?= json_encode($puertosRaw) ?>;
const ctx = document.getElementById('graficoPuertos').getContext('2d');

const graficoPuertos = new Chart(ctx, {
    type: 'bar',
    data: {
        labels: <?= json_encode($labelsPuertos) ?>,
        datasets: [{
            label: 'Bloqueos por Puerto',
            data: <?= json_encode($valoresBloqueos) ?>,
            backgroundColor: <?= json_encode($bgColors) ?>,
            borderColor: <?= json_encode($borderColors) ?>,
            borderWidth: 1
        }]
    },
    options: {
        indexAxis: 'y',
        responsive: true,
        maintainAspectRatio: false,
        scales: {
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
                
                const bsModal = new bootstrap.Modal(modalEl);
                bsModal.show();
                
                const fechaInicio = document.getElementById('fecha_inicio').value;
                const fechaFin = document.getElementById('fecha_fin').value;
                
                fetch(`?ajax_detalle_puerto=1&puerto=${puertoNum}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`)
                    .then(response => response.text())
                    .then(html => {
                        modalBody.innerHTML = html;
                    })
                    .catch(error => {
                        modalBody.innerHTML = `<div class="alert alert-danger">Error al cargar datos del servidor.</div>`;
                    });
            }
        }
    }
});

function exportarDetallePuertoWord(puerto) {
    const fechaInicio = document.getElementById('fecha_inicio').value;
    const fechaFin = document.getElementById('fecha_fin').value;
    window.location.href = `generar_word_puertos.php?puerto=${puerto}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`;
}
</script>

<?php include 'views/footer.php'; ?>
