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
// ENDPOINT AJAX: Detalle de Conexiones Entrantes o Salientes por País
// -------------------------------------------------------------------------
if (isset($_GET['ajax_detalle_pais'])) {
    if (ob_get_level())
        ob_clean();

    $pais = trim($_GET['pais'] ?? '');
    $direccion = $_GET['direccion'] ?? 'entrante'; // 'entrante' | 'saliente'
    $fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
    $fechaFin = $_GET['fecha_fin'] ?? date('Y-m-d');

    $sqlInicio = $fechaInicio . ' 00:00:00';
    $sqlFin = $fechaFin . ' 23:59:59';

    $condPais = ($pais === 'Desconocido' || $pais === '')
        ? "(i.pais IS NULL OR i.pais = '' OR i.pais = 'Desconocido')"
        : "i.pais = ?";

    if ($direccion === 'saliente') {
        $sqlDetalle = "
            SELECT f.fecha_evento, f.ip_origen, f.ip_destino, f.puerto_destino, f.protocolo, f.accion, i.reputacion
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_destino = i.ip COLLATE utf8mb4_unicode_ci
            WHERE (f.ip_origen LIKE '192.168.%' OR f.ip_origen LIKE '10.%' OR f.ip_origen LIKE '172.16.%')
              AND f.ip_destino NOT LIKE '192.168.%'
              AND f.ip_destino NOT LIKE '10.%'
              AND f.ip_destino NOT LIKE '172.16.%'
              AND f.fecha_evento BETWEEN ? AND ?
              AND {$condPais}
            ORDER BY f.fecha_evento DESC
            LIMIT 250
        ";
    } else {
        $sqlDetalle = "
            SELECT f.fecha_evento, f.ip_origen, f.ip_destino, f.puerto_destino, f.protocolo, f.accion, i.reputacion
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
            WHERE f.ip_origen NOT LIKE '192.168.%'
              AND f.ip_origen NOT LIKE '10.%'
              AND f.ip_origen NOT LIKE '172.16.%'
              AND f.fecha_evento BETWEEN ? AND ?
              AND {$condPais}
            ORDER BY f.fecha_evento DESC
            LIMIT 250
        ";
    }

    $params = [$sqlInicio, $sqlFin];
    if ($pais !== 'Desconocido' && $pais !== '') {
        $params[] = $pais;
    }

    $stmt = $pdo->prepare($sqlDetalle);
    $stmt->execute($params);
    $eventos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if (empty($eventos)) {
        echo '<div class="alert alert-info mb-0">No se encontraron eventos detallados para este país en el rango seleccionado.</div>';
        exit;
    }

    echo '<div class="table-responsive"><table class="table table-sm table-striped table-hover align-middle mb-0">';
    echo '<thead class="table-dark"><tr><th>Fecha / Hora</th><th>IP Origen</th><th>IP Destino</th><th>Puerto</th><th>Protocolo</th><th>Acción</th></tr></thead><tbody>';

    foreach ($eventos as $ev) {
        $ipOrig = htmlspecialchars($ev['ip_origen']);
        $ipDest = htmlspecialchars($ev['ip_destino'] ?? 'N/A');
        $accion = strtoupper($ev['accion']);
        $badgeAccion = ($accion === 'BLOCK' || $accion === 'DROP') ? 'bg-danger' : 'bg-success';

        // Enlace a VirusTotal para la IP externa (origen en entrantes, destino en salientes)
        if ($direccion === 'saliente') {
            $ipDestHtml = '<a href="https://www.virustotal.com/gui/ip-address/' . $ipDest . '" target="_blank" class="fw-bold text-decoration-none">' . $ipDest . ' <i class="bi bi-box-arrow-up-right" style="font-size:10px;"></i></a>';
            $ipOrigHtml = '<span class="badge bg-secondary">' . $ipOrig . '</span>';
        } else {
            $ipOrigHtml = '<a href="https://www.virustotal.com/gui/ip-address/' . $ipOrig . '" target="_blank" class="fw-bold text-decoration-none">' . $ipOrig . ' <i class="bi bi-box-arrow-up-right" style="font-size:10px;"></i></a>';
            $ipDestHtml = '<code>' . $ipDest . '</code>';
        }

        echo '<tr>
            <td><small>' . htmlspecialchars($ev['fecha_evento']) . '</small></td>
            <td>' . $ipOrigHtml . '</td>
            <td>' . $ipDestHtml . '</td>
            <td><span class="badge bg-light text-dark border fw-bold">' . (int) $ev['puerto_destino'] . '</span></td>
            <td><small>' . strtoupper(htmlspecialchars($ev['protocolo'])) . '</small></td>
            <td><span class="badge ' . $badgeAccion . '">' . $accion . '</span></td>
        </tr>';
    }
    echo '</tbody></table></div>';
    exit;
}

// -------------------------------------------------------------------------
// CONSULTAS PRINCIPALES: ENTRANTES VS SALIENTES POR PAÍS
// -------------------------------------------------------------------------
$fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
$fechaFin = $_GET['fecha_fin'] ?? date('Y-m-d');

$sqlInicio = $fechaInicio . ' 00:00:00';
$sqlFin = $fechaFin . ' 23:59:59';

// 1. Conexiones Entrantes por País (Origen externo -> Red local/WAN)
$sqlEntrantes = "
    SELECT 
        COALESCE(NULLIF(TRIM(i.pais), ''), 'Desconocido') AS pais,
        COUNT(*) AS total,
        SUM(CASE WHEN f.accion = 'BLOCK' THEN 1 ELSE 0 END) AS bloqueados
    FROM firewall_eventos f
    LEFT JOIN ips i ON f.ip_origen = i.ip COLLATE utf8mb4_unicode_ci
    WHERE f.ip_origen NOT LIKE '192.168.%'
      AND f.ip_origen NOT LIKE '10.%'
      AND f.ip_origen NOT LIKE '172.16.%'
      AND f.fecha_evento BETWEEN ? AND ?
    GROUP BY pais
    ORDER BY total DESC
";
$stmtEnt = $pdo->prepare($sqlEntrantes);
$stmtEnt->execute([$sqlInicio, $sqlFin]);
$paisesEntrantes = $stmtEnt->fetchAll(PDO::FETCH_ASSOC);

// 2. Conexiones Salientes por País (Equipo interno -> Destino externo)
$sqlSalientes = "
    SELECT 
        COALESCE(NULLIF(TRIM(i.pais), ''), 'Desconocido') AS pais,
        COUNT(*) AS total,
        SUM(CASE WHEN f.accion = 'PASS' THEN 1 ELSE 0 END) AS permitidos
    FROM firewall_eventos f
    LEFT JOIN ips i ON f.ip_destino = i.ip COLLATE utf8mb4_unicode_ci
    WHERE (f.ip_origen LIKE '192.168.%' OR f.ip_origen LIKE '10.%' OR f.ip_origen LIKE '172.16.%')
      AND f.ip_destino NOT LIKE '192.168.%'
      AND f.ip_destino NOT LIKE '10.%'
      AND f.ip_destino NOT LIKE '172.16.%'
      AND f.ip_destino NOT LIKE '224.%'
      AND f.ip_destino != '255.255.255.255'
      AND f.fecha_evento BETWEEN ? AND ?
    GROUP BY pais
    ORDER BY total DESC
";
$stmtSal = $pdo->prepare($sqlSalientes);
$stmtSal->execute([$sqlInicio, $sqlFin]);
$paisesSalientes = $stmtSal->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-4 mb-5">
    <h2 class="mb-3"><i class="bi bi-globe-americas text-primary me-2"></i>Tráfico Geográfico por País</h2>

    <!-- Filtro por Fechas -->
    <div class="card mb-4 shadow-sm">
        <div class="card-body py-3">
            <form method="GET" id="formFiltro" class="row g-3 align-items-end">
                <div class="col-md-4">
                    <label for="fecha_inicio" class="form-label small fw-bold mb-1">Fecha Inicio</label>
                    <input type="date" class="form-control form-control-sm" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-4">
                    <label for="fecha_fin" class="form-label small fw-bold mb-1">Fecha Fin</label>
                    <input type="date" class="form-control form-control-sm" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-4 d-flex gap-2">
                    <button type="submit" class="btn btn-sm btn-primary w-50">Filtrar</button>
                    <a href="paises.php" class="btn btn-sm btn-secondary w-50">Limpiar</a>
                </div>
            </form>
        </div>
    </div>

    <!-- Dos Columnas: Conexiones Entrantes vs. Conexiones Salientes -->
    <div class="row g-4">
        <!-- COLUMNA 1: CONEXIONES ENTRANTES -->
        <div class="col-lg-6">
            <div class="card shadow-sm h-100 border-top border-danger border-3">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-box-arrow-in-right text-danger me-2"></i>Conexiones Entrantes (Origen Externo)</span>
                    <span class="badge bg-danger"><?= count($paisesEntrantes) ?> países</span>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="tablaEntrantes" class="table table-sm table-striped table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>País Origen</th>
                                    <th class="text-end">Eventos</th>
                                    <th class="text-end">Bloqueos</th>
                                    <th class="text-end">Detalle</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($paisesEntrantes as $row): ?>
                                    <tr>
                                        <td class="fw-semibold"><?= htmlspecialchars($row['pais']) ?></td>
                                        <td class="text-end"><?= number_format($row['total']) ?></td>
                                        <td class="text-end"><span class="badge bg-danger"><?= number_format($row['bloqueados']) ?></span></td>
                                        <td class="text-end">
                                            <button type="button" class="btn btn-sm btn-outline-primary ver-detalle-pais"
                                                    data-pais="<?= htmlspecialchars($row['pais']) ?>"
                                                    data-direccion="entrante">
                                                <i class="bi bi-eye"></i> Ver
                                            </button>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>

        <!-- COLUMNA 2: CONEXIONES SALIENTES -->
        <div class="col-lg-6">
            <div class="card shadow-sm h-100 border-top border-info border-3">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <span><i class="bi bi-box-arrow-up-right text-info me-2"></i>Conexiones Salientes (Destino Externo)</span>
                    <span class="badge bg-info text-dark"><?= count($paisesSalientes) ?> países</span>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table id="tablaSalientes" class="table table-sm table-striped table-hover align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>País Destino</th>
                                    <th class="text-end">Eventos</th>
                                    <th class="text-end">Permitidos</th>
                                    <th class="text-end">Detalle</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($paisesSalientes as $row): ?>
                                    <tr>
                                        <td class="fw-semibold"><?= htmlspecialchars($row['pais']) ?></td>
                                        <td class="text-end"><?= number_format($row['total']) ?></td>
                                        <td class="text-end"><span class="badge bg-success"><?= number_format($row['permitidos']) ?></span></td>
                                        <td class="text-end">
                                            <button type="button" class="btn btn-sm btn-outline-info text-dark ver-detalle-pais"
                                                    data-pais="<?= htmlspecialchars($row['pais']) ?>"
                                                    data-direccion="saliente">
                                                <i class="bi bi-eye"></i> Ver
                                            </button>
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

<!-- Modal para Detalles del País (Entrante / Saliente) -->
<div class="modal fade" id="modalDetallePais" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-xl modal-dialog-scrollable">
        <div class="modal-content">
            <div class="modal-header bg-dark text-white">
                <h5 class="modal-title" id="modalDetallePaisTitulo">Detalle de Conexiones</h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Cerrar"></button>
            </div>
            <div class="modal-body" id="modalDetallePaisBody">
                <div class="text-center py-4">
                    <div class="spinner-border text-primary" role="status"></div>
                    <p class="mt-2 text-muted">Cargando conexiones...</p>
                </div>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    if (typeof window.jQuery !== 'undefined' && typeof window.jQuery.fn.DataTable !== 'undefined') {
        window.jQuery('#tablaEntrantes, #tablaSalientes').DataTable({
            pageLength: 15,
            order: [[1, 'desc']]
        });
    }

    document.addEventListener('click', function(e) {
        const btn = e.target.closest('.ver-detalle-pais');
        if (!btn) return;

        e.preventDefault();
        const pais = btn.getAttribute('data-pais');
        const direccion = btn.getAttribute('data-direccion');
        const fechaInicio = document.getElementById('fecha_inicio').value;
        const fechaFin = document.getElementById('fecha_fin').value;

        const titulo = (direccion === 'saliente')
            ? `Conexiones Salientes hacia: ${pais}`
            : `Conexiones Entrantes desde: ${pais}`;

        document.getElementById('modalDetallePaisTitulo').textContent = titulo;
        const modalBody = document.getElementById('modalDetallePaisBody');
        modalBody.innerHTML = `
            <div class="text-center py-4">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2 text-muted">Consultando eventos...</p>
            </div>`;

        const modalEl = document.getElementById('modalDetallePais');
        bootstrap.Modal.getOrCreateInstance(modalEl).show();

        fetch(`paises.php?ajax_detalle_pais=1&pais=${encodeURIComponent(pais)}&direccion=${direccion}&fecha_inicio=${fechaInicio}&fecha_fin=${fechaFin}`)
            .then(r => r.text())
            .then(html => { modalBody.innerHTML = html; })
            .catch(() => { modalBody.innerHTML = '<div class="alert alert-danger">Error al cargar los detalles.</div>'; });
    });
});
</script>

<?php include 'views/footer.php'; ?>