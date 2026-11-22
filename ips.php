<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
date_default_timezone_set("America/Montevideo");
// Cargar el archivo centralizador de la raíz
require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// 1. Obtener filtros de fecha y búsqueda por IP opcionales
$fechaInicio = $_GET['fecha_inicio'] ?? date('Y-m-d');
$fechaFin    = $_GET['fecha_fin'] ?? date('Y-m-d');
$ipBuscar    = trim($_GET['ip_buscar'] ?? '');

// Construir la consulta SQL dinámica según los filtros
$whereClauses = ["f.ip_origen NOT LIKE '192.168.1.%'"]; // Excluir red interna por defecto
$params = [];

if (!empty($fechaInicio)) {
    $whereClauses[] = "f.fecha_evento >= ?";
    $params[] = $fechaInicio . ' 00:00:00';
}
if (!empty($fechaFin)) {
    $whereClauses[] = "f.fecha_evento <= ?";
    $params[] = $fechaFin . ' 23:59:59';
}
if (!empty($ipBuscar)) {
    $whereClauses[] = "f.ip_origen LIKE ?";
    $params[] = '%' . $ipBuscar . '%';
}

$sqlWhere = "WHERE " . implode(" AND ", $whereClauses);

$sql = "
    SELECT
        f.ip_origen,
        COUNT(*) cantidad,
        MIN(f.fecha_evento) primera_fecha,
        MAX(f.fecha_evento) ultima_fecha,
        i.pais,
        i.abuse_score,
        i.reputacion
    FROM firewall_eventos f
    LEFT JOIN ips i
    ON i.ip = f.ip_origen
    {$sqlWhere}
    GROUP BY f.ip_origen
    ORDER BY cantidad DESC
";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$ips = $stmt->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-3">

    <!-- Formulario de Filtros (Fechas e IP) -->
    <div class="card mb-4 shadow-sm">
        <div class="card-body">
            <form method="GET" id="formFiltro" class="row g-3 align-items-end">
                <div class="col-md-3">
                    <label for="fecha_inicio" class="form-label">Fecha Inicio</label>
                    <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($fechaInicio) ?>">
                </div>
                <div class="col-md-3">
                    <label for="fecha_fin" class="form-label">Fecha Fin</label>
                    <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($fechaFin) ?>">
                </div>
                <div class="col-md-3">
                    <label for="ip_buscar" class="form-label">Filtrar por IP</label>
                    <input type="text" class="form-control" id="ip_buscar" name="ip_buscar" placeholder="Ej: 190.64 o IP completa" value="<?= htmlspecialchars($ipBuscar) ?>">
                </div>
                <div class="col-md-3 d-flex gap-2">
                    <button type="submit" class="btn btn-primary w-50">Filtrar</button>
                    <a href="<?= strtok($_SERVER["REQUEST_URI"], '?') ?>" class="btn btn-secondary w-50">Limpiar</a>
                </div>
            </form>
        </div>
    </div>

    <div class="card shadow-sm">
        <div class="card-header bg-dark text-white">
            IPs Únicas (Excluyendo Red Local)
        </div>
        <div class="card-body">
            <table id="tablaIps" class="table table-sm table-hover align-middle">
                <thead>
                    <tr>
                        <th>IP (VirusTotal)</th>
                        <th>País</th>
                        <th>Eventos</th>
                        <th>Primer Avistamiento</th>
                        <th>Último Avistamiento</th>
                        <th>Score</th>
                        <th>Reputación</th>
                    </tr>
                </thead>
                <tbody>
                <?php foreach($ips as $row): ?>
                    <?php
                        // Estilizar reputación de forma robusta e insensible a mayúsculas/minúsculas
                        $repVal = trim($row['reputacion'] ?? 'DESCONOCIDA');
                        if ($repVal === '') { $repVal = 'DESCONOCIDA'; }
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
                    ?>
                    <tr>
                        <td><code><?= $enlaceIp ?></code></td>
                        <td><?= htmlspecialchars($row['pais'] ?? 'Desconocido') ?></td>
                        <td><?= number_format($row['cantidad']) ?></td>
                        <td><?= htmlspecialchars($row['primera_fecha']) ?></td>
                        <td><?= htmlspecialchars($row['ultima_fecha']) ?></td>
                        <td><?= htmlspecialchars($row['abuse_score'] ?? 0) ?></td>
                        <td><?= $badgeRep ?></td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>

</div>

<script>
$(function(){
    $('#tablaIps').DataTable({
        pageLength: 50,
        order: [[2, 'desc']]
    });
});
</script>

<?php include 'views/footer.php'; ?>
