<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set("America/Montevideo");

require_once __DIR__ . '/bootstrap.php';
use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// -------------------------------------------------------------------------
// ENDPOINT AJAX: Paginación Server-Side para Logs del Firewall
// -------------------------------------------------------------------------
if (isset($_GET['ajax_listar_logs'])) {
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    if (ob_get_level()) ob_clean();
    header('Content-Type: application/json; charset=utf-8');

    $draw         = (int) ($_GET['draw'] ?? 1);
    $start        = max(0, (int) ($_GET['start'] ?? 0));
    $length       = min(200, max(10, (int) ($_GET['length'] ?? 50)));
    $searchValue  = trim($_GET['search']['value'] ?? '');

    $hoy          = date('Y-m-d');
    $fechaInicio  = $_GET['fecha_inicio'] ?? $hoy;
    $fechaFin     = $_GET['fecha_fin'] ?? $hoy;
    $paisFiltro   = trim($_GET['pais'] ?? '');
    $puertoFiltro = trim($_GET['puerto'] ?? '');

    $orderColIdx = (int) ($_GET['order'][0]['column'] ?? 0);
    $orderDir    = (strtoupper($_GET['order'][0]['dir'] ?? 'DESC') === 'ASC') ? 'ASC' : 'DESC';
    $columnasOrden = [
        0 => 'f.fecha_evento',
        1 => 'f.ip_origen',
        2 => 'i.pais',
        3 => 'i.reputacion',
        4 => 'f.puerto_destino',
        5 => 'f.accion',
        6 => 'f.protocolo'
    ];
    $orderBy = $columnasOrden[$orderColIdx] ?? 'f.fecha_evento';

    $whereClauses = [
        "f.ip_origen NOT LIKE '192.168.1.%'",
        "f.fecha_evento BETWEEN ? AND ?"
    ];
    $baseParams = [
        $fechaInicio . ' 00:00:00',
        $fechaFin . ' 23:59:59'
    ];

    if ($paisFiltro !== '') {
        $whereClauses[] = "i.pais = ?";
        $baseParams[] = $paisFiltro;
    }

    if ($puertoFiltro !== '') {
        $whereClauses[] = "f.puerto_destino = ?";
        $baseParams[] = (int) $puertoFiltro;
    }

    $whereBaseSql = "WHERE " . implode(" AND ", $whereClauses);

    try {
        // 1. Total de registros con los filtros del formulario
        $sqlTotal = "
            SELECT COUNT(*)
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
            {$whereBaseSql}
        ";
        $stmtTotal = $pdo->prepare($sqlTotal);
        $stmtTotal->execute($baseParams);
        $recordsTotal = (int) $stmtTotal->fetchColumn();

        // 2. Filtro adicional del buscador de DataTables
        $whereFullSql = $whereBaseSql;
        $fullParams = $baseParams;
        if ($searchValue !== '') {
            $whereFullSql .= " AND (f.ip_origen LIKE ? OR i.pais LIKE ? OR f.puerto_destino LIKE ? OR f.protocolo LIKE ? OR f.accion LIKE ?)";
            $like = '%' . $searchValue . '%';
            array_push($fullParams, $like, $like, $like, $like, $like);
        }

        $sqlFiltered = "
            SELECT COUNT(*)
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
            {$whereFullSql}
        ";
        $stmtFilt = $pdo->prepare($sqlFiltered);
        $stmtFilt->execute($fullParams);
        $recordsFiltered = (int) $stmtFilt->fetchColumn();

        // 3. Consulta paginada real
        $sqlData = "
            SELECT
                f.fecha_evento,
                f.ip_origen,
                i.pais,
                i.reputacion,
                f.puerto_destino,
                f.accion,
                f.protocolo
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
            {$whereFullSql}
            ORDER BY {$orderBy} {$orderDir}
            LIMIT {$start}, {$length}
        ";
        $stmtData = $pdo->prepare($sqlData);
        $stmtData->execute($fullParams);
        $rows = $stmtData->fetchAll(PDO::FETCH_ASSOC);

        $data = [];
        foreach ($rows as $row) {
            $ipOrigen = htmlspecialchars($row['ip_origen']);
            $enlaceIp = '<code><a href="https://www.virustotal.com/gui/ip-address/' . $ipOrigen . '" target="_blank" class="text-decoration-none fw-bold" title="Ver en VirusTotal">' . $ipOrigen . ' <i class="bi bi-box-arrow-up-right" style="font-size: 11px;"></i></a></code>';

            $repVal = trim($row['reputacion'] ?? '');
            $rep = strtolower($repVal);
            if ($rep === 'mala' || $rep === 'maliciosa' || $rep === 'baja') {
                $badgeRep = '<span class="badge bg-danger">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'media' || $rep === 'sospechosa') {
                $badgeRep = '<span class="badge bg-warning text-dark">' . htmlspecialchars($repVal) . '</span>';
            } elseif ($rep === 'buena' || $rep === 'alta') {
                $badgeRep = '<span class="badge bg-success">' . htmlspecialchars($repVal) . '</span>';
            } else {
                $textoMostrar = ($repVal === '') ? 'Desconocida' : $repVal;
                $badgeRep = '<span class="badge bg-secondary">' . htmlspecialchars($textoMostrar) . '</span>';
            }

            $accionStr = strtoupper(trim($row['accion'] ?? ''));
            $badgeAccion = ($accionStr === 'BLOCK' || $accionStr === 'DROP')
                ? '<span class="badge bg-danger">' . htmlspecialchars($accionStr) . '</span>'
                : '<span class="badge bg-success">' . htmlspecialchars($accionStr) . '</span>';

            $data[] = [
                htmlspecialchars($row['fecha_evento']),
                $enlaceIp,
                htmlspecialchars($row['pais'] ?? 'Desconocido'),
                $badgeRep,
                htmlspecialchars((string) $row['puerto_destino']),
                $badgeAccion,
                strtoupper(htmlspecialchars($row['protocolo'] ?? ''))
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

// -------------------------------------------------------------------------
// VISTA HTML PRINCIPAL
// -------------------------------------------------------------------------
$hoy = date('Y-m-d');
$fechaInicio  = $_GET['fecha_inicio'] ?? $hoy;
$fechaFin     = $_GET['fecha_fin'] ?? $hoy;
$paisFiltro   = $_GET['pais'] ?? '';
$puertoFiltro = $_GET['puerto'] ?? '';

$listaPaises = $pdo->query("SELECT DISTINCT pais FROM ips WHERE pais IS NOT NULL AND pais != '' ORDER BY pais ASC")->fetchAll(PDO::FETCH_COLUMN);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-3 mb-5">

    <!-- Formulario de Filtros -->
    <div class="card mb-3 shadow-sm">
        <div class="card-header bg-secondary text-white">
            Filtros de Búsqueda
        </div>
        <div class="card-body">
            <form method="GET" id="formFiltrosLogs" class="row g-3 align-items-end">
                <div class="col-md-3">
                    <label for="fecha_inicio" class="form-label">Fecha Inicio</label>
                    <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-3">
                    <label for="fecha_fin" class="form-label">Fecha Fin</label>
                    <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-2">
                    <label for="pais" class="form-label">País</label>
                    <select class="form-select" id="pais" name="pais">
                        <option value="">-- Todos --</option>
                        <?php foreach ($listaPaises as $p): ?>
                            <option value="<?= htmlspecialchars($p) ?>" <?= ($paisFiltro === $p) ? 'selected' : '' ?>>
                                <?= htmlspecialchars($p) ?>
                            </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="col-md-2">
                    <label for="puerto" class="form-label">Puerto Destino</label>
                    <input type="number" class="form-control" id="puerto" name="puerto" placeholder="Ej: 80, 443" value="<?= htmlspecialchars($puertoFiltro) ?>">
                </div>
                <div class="col-md-2 d-flex gap-2">
                    <button type="submit" class="btn btn-primary w-100">Filtrar</button>
                    <a href="logs.php" class="btn btn-outline-secondary">Limpiar</a>
                </div>
            </form>
        </div>
    </div>

    <div class="card shadow-sm">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <span>Logs Firewall (Excluyendo Red Local)</span>
            <span class="badge bg-info text-dark" id="badgeTotalLogs">Cargando...</span>
        </div>

        <div class="card-body">
            <div class="table-responsive">
                <table id="tablaLogs" class="table table-striped table-bordered align-middle w-100">
                    <thead>
                    <tr>
                        <th>Fecha</th>
                        <th>IP Origen</th>
                        <th>País</th>
                        <th>Reputación</th>
                        <th>Puerto</th>
                        <th>Acción</th>
                        <th>Protocolo</th>
                    </tr>
                    </thead>
                    <tbody></tbody>
                </table>
            </div>
        </div>
    </div>

</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    if (typeof window.jQuery !== 'undefined' && typeof window.jQuery.fn.DataTable !== 'undefined') {
        window.jQuery('#tablaLogs').DataTable({
            processing: true,
            serverSide: true,
            pageLength: 50,
            order: [[0, 'desc']],
            ajax: {
                url: 'logs.php',
                data: function(d) {
                    d.ajax_listar_logs = 1;
                    d.fecha_inicio = document.getElementById('fecha_inicio').value;
                    d.fecha_fin    = document.getElementById('fecha_fin').value;
                    d.pais         = document.getElementById('pais').value;
                    d.puerto       = document.getElementById('puerto').value;
                }
            },
            drawCallback: function(settings) {
                if (settings.json && typeof settings.json.recordsFiltered !== 'undefined') {
                    document.getElementById('badgeTotalLogs').textContent =
                        Number(settings.json.recordsFiltered).toLocaleString() + ' registros';
                }
            }
        });
    }
});
</script>

<?php include 'views/footer.php'; ?>