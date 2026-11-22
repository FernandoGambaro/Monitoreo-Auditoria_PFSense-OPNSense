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
// ENDPOINT AJAX: Ejecución de limpieza por lotes (evita bloqueos y timeouts)
// -------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ajax_limpiar'])) {
    ini_set('display_errors', 0);
    set_time_limit(300);

    if (session_status() === PHP_SESSION_ACTIVE) {
        session_write_close();
    }
    if (ob_get_level()) ob_clean();
    header('Content-Type: application/json; charset=utf-8');

    $tipo         = $_POST['tipo'] ?? '';
    $diasPass     = max(1, (int) ($_POST['dias_pass'] ?? 30));
    $diasBlock    = max(7, (int) ($_POST['dias_block'] ?? 90));
    $diasAuditado = max(0, (int) ($_POST['dias_auditado'] ?? 7));
    $loteMax      = 25000;

    try {
        $eliminados = 0;

        if ($tipo === 'auditados_confiables') {
            // En MariaDB/MySQL, DELETE con LIMIT requiere operar sobre una sola tabla (usando subconsulta)
            $sql = "
                DELETE FROM firewall_eventos
                WHERE id IN (
                    SELECT sub.id FROM (
                        SELECT f.id
                        FROM firewall_eventos f
                        INNER JOIN ips_externas_confiables c 
                            ON f.ip_destino = c.ip COLLATE utf8mb4_unicode_ci
                        WHERE (f.accion = 'PASS' OR f.accion = 'pass')
                          AND f.fecha_evento < DATE_SUB(NOW(), INTERVAL :dias DAY)
                        ORDER BY f.id ASC
                        LIMIT {$loteMax}
                    ) AS sub
                )
            ";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':dias' => $diasAuditado]);
            $eliminados = $stmt->rowCount();

        } elseif ($tipo === 'historico_pass') {
            $sql = "
                DELETE FROM firewall_eventos
                WHERE (accion = 'PASS' OR accion = 'pass')
                  AND fecha_evento < DATE_SUB(NOW(), INTERVAL :dias DAY)
                LIMIT {$loteMax}
            ";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':dias' => $diasPass]);
            $eliminados = $stmt->rowCount();

        } elseif ($tipo === 'historico_block') {
            $sql = "
                DELETE FROM firewall_eventos
                WHERE (accion = 'BLOCK' OR accion = 'block')
                  AND fecha_evento < DATE_SUB(NOW(), INTERVAL :dias DAY)
                LIMIT {$loteMax}
            ";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':dias' => $diasBlock]);
            $eliminados = $stmt->rowCount();

        } elseif ($tipo === 'optimizar_tabla') {
            // ANALYZE TABLE actualiza índices y estadísticas en milisegundos sin bloquear InnoDB ni disparar el timeout del proxy web
            $stmtOpt = $pdo->query("ANALYZE TABLE firewall_eventos");
            $resultadoOpt = $stmtOpt ? $stmtOpt->fetchAll(PDO::FETCH_ASSOC) : [];
            if ($stmtOpt) {
                $stmtOpt->closeCursor();
            }

            $detalleMsg = !empty($resultadoOpt) ? ($resultadoOpt[0]['Msg_text'] ?? 'OK') : 'OK';
            echo json_encode([
                'ok'         => true,
                'eliminados' => 0,
                'continuar'  => false,
                'mensaje'    => 'Estadísticas e índices actualizados (' . $detalleMsg . '). Nota: InnoDB reutiliza automáticamente el espacio liberado.'
            ]);
            exit;
        
        } else {
            echo json_encode(['ok' => false, 'error' => 'Tipo de limpieza no válido.']);
            exit;
        }

        echo json_encode([
            'ok'         => true,
            'eliminados' => $eliminados,
            'continuar'  => ($eliminados >= $loteMax)
        ]);
    } catch (Throwable $e) {
        echo json_encode([
            'ok'    => false,
            'error' => $e->getMessage()
        ]);
    }
    exit;
}

// -------------------------------------------------------------------------
// ESTADÍSTICAS ACTUALES DE LA TABLA firewall_eventos
// -------------------------------------------------------------------------
$stats = [
    'total'         => 0,
    'total_pass'    => 0,
    'total_block'   => 0,
    'fecha_min'     => 'N/A',
    'tamano_mb'     => 0,
    'auditados_est' => 0
];

try {
    $rowStats = $pdo->query("
        SELECT 
            COUNT(*) AS total,
            SUM(CASE WHEN accion = 'PASS' OR accion = 'pass' THEN 1 ELSE 0 END) AS total_pass,
            SUM(CASE WHEN accion = 'BLOCK' OR accion = 'block' THEN 1 ELSE 0 END) AS total_block,
            MIN(fecha_evento) AS fecha_min
        FROM firewall_eventos
    ")->fetch(PDO::FETCH_ASSOC);

    if ($rowStats) {
        $stats['total']       = (int) ($rowStats['total'] ?? 0);
        $stats['total_pass']  = (int) ($rowStats['total_pass'] ?? 0);
        $stats['total_block'] = (int) ($rowStats['total_block'] ?? 0);
        $stats['fecha_min']   = $rowStats['fecha_min'] ?: 'Sin registros';
    }

    // Tamaño físico aproximado en MB
    $stmtSize = $pdo->query("
        SELECT ROUND((DATA_LENGTH + INDEX_LENGTH) / 1024 / 1024, 2) AS size_mb
        FROM information_schema.TABLES
        WHERE TABLE_SCHEMA = DATABASE()
          AND TABLE_NAME = 'firewall_eventos'
    ");
    $stats['tamano_mb'] = (float) ($stmtSize->fetchColumn() ?: 0);

    // Estimación de eventos PASS hacia IPs ya confiables
    $stmtAud = $pdo->query("
        SELECT COUNT(*)
        FROM firewall_eventos f
        INNER JOIN ips_externas_confiables c 
            ON f.ip_destino = c.ip COLLATE utf8mb4_unicode_ci
        WHERE (f.accion = 'PASS' OR f.accion = 'pass')
    ");
    $stats['auditados_est'] = (int) ($stmtAud->fetchColumn() ?: 0);
} catch (Exception $e) {
    $errorStats = $e->getMessage();
}

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container-fluid mt-4 mb-5">
    <div class="d-flex justify-content-between align-items-center mb-3">
        <h2 class="mb-0"><i class="bi bi-database-gear text-warning me-2"></i>Mantenimiento y Limpieza de Base de Datos</h2>
        <button type="button" class="btn btn-outline-secondary btn-sm" id="btnOptimizarTabla">
            <i class="bi bi-speedometer2 me-1"></i> Optimizar Tabla (OPTIMIZE)
        </button>
    </div>

    <?php if (!empty($errorStats)): ?>
        <div class="alert alert-danger"><?= htmlspecialchars($errorStats) ?></div>
    <?php endif; ?>

    <!-- Tarjetas de Diagnóstico -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card shadow-sm border-start border-primary border-4 h-100">
                <div class="card-body">
                    <div class="text-muted small fw-bold text-uppercase">Total Eventos</div>
                    <h3 class="mb-0 mt-1"><?= number_format($stats['total']) ?></h3>
                    <small class="text-muted">Tamaño: <strong><?= $stats['tamano_mb'] ?> MB</strong></small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card shadow-sm border-start border-success border-4 h-100">
                <div class="card-body">
                    <div class="text-muted small fw-bold text-uppercase">Tráfico Permitido (PASS)</div>
                    <h3 class="mb-0 mt-1 text-success"><?= number_format($stats['total_pass']) ?></h3>
                    <small class="text-muted">Auditados en Whitelist: <strong><?= number_format($stats['auditados_est']) ?></strong></small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card shadow-sm border-start border-danger border-4 h-100">
                <div class="card-body">
                    <div class="text-muted small fw-bold text-uppercase">Tráfico Bloqueado (BLOCK)</div>
                    <h3 class="mb-0 mt-1 text-danger"><?= number_format($stats['total_block']) ?></h3>
                    <small class="text-muted">Historial de amenazas</small>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card shadow-sm border-start border-info border-4 h-100">
                <div class="card-body">
                    <div class="text-muted small fw-bold text-uppercase">Registro Más Antiguo</div>
                    <h5 class="mb-0 mt-2"><?= htmlspecialchars($stats['fecha_min']) ?></h5>
                    <small class="text-muted">Inicio del histórico</small>
                </div>
            </div>
        </div>
    </div>

    <!-- Barra de progreso global para operaciones de limpieza -->
    <div id="panelProgreso" class="card shadow-sm mb-4 border-warning d-none">
        <div class="card-body">
            <div class="d-flex justify-content-between align-items-center mb-2">
                <span class="fw-bold text-dark" id="textoProgreso"><span class="spinner-border spinner-border-sm text-warning me-2"></span>Ejecutando limpieza por lotes...</span>
                <span class="badge bg-dark fs-6" id="contadorEliminados">0 registros eliminados</span>
            </div>
            <div class="progress" style="height: 20px;">
                <div id="barraProgreso" class="progress-bar progress-bar-striped progress-bar-animated bg-warning text-dark fw-bold" style="width: 100%;">
                    Procesando lotes de 25,000 filas...
                </div>
            </div>
        </div>
    </div>

    <!-- Opciones de Limpieza -->
    <div class="row g-4">
        <!-- Opción 1: Limpiar Tráfico Auditado (IPs Confiables) -->
        <div class="col-lg-6">
            <div class="card shadow-sm h-100 border-top border-success border-3">
                <div class="card-header bg-dark text-white">
                    <i class="bi bi-check2-all text-success me-2"></i>Limpiar Tráfico Saliente Ya Auditado
                </div>
                <div class="card-body d-flex flex-column justify-content-between">
                    <div>
                        <p class="text-muted small">
                            Elimina los registros permitidos (<code>PASS</code>) dirigidos hacia IPs externas que ya fueron aprobadas en tu lista blanca (<strong>IPs Confiables</strong>), liberando espacio sin perder registros pendientes de revisión.
                        </p>
                        <div class="mb-3">
                            <label for="diasAuditado" class="form-label fw-bold small">Conservar registros de los últimos (días):</label>
                            <input type="number" id="diasAuditado" class="form-control form-control-sm" value="7" min="0" max="365">
                            <div class="form-text">Usa <code>0</code> para limpiar todo el tráfico auditado hasta el momento, o <code>7</code> para conservar la última semana.</div>
                        </div>
                    </div>
                    <button type="button" class="btn btn-success w-100" id="btnLimpiarAuditados">
                        <i class="bi bi-trash3 me-1"></i> Limpiar Registros Auditados
                    </button>
                </div>
            </div>
        </div>

        <!-- Opción 2: Depuración Histórica por Antigüedad -->
        <div class="col-lg-6">
            <div class="card shadow-sm h-100 border-top border-danger border-3">
                <div class="card-header bg-dark text-white">
                    <i class="bi bi-calendar-x text-danger me-2"></i>Depuración Histórica por Antigüedad
                </div>
                <div class="card-body d-flex flex-column justify-content-between">
                    <div>
                        <p class="text-muted small">
                            Elimina eventos antiguos de <code>firewall_eventos</code> según su tipo de acción para mantener ágiles el Dashboard, los Logs y los reportes.
                        </p>
                        <div class="row g-2 mb-3">
                            <div class="col-md-6">
                                <label for="diasPass" class="form-label fw-bold small">Retener PASS (días):</label>
                                <input type="number" id="diasPass" class="form-control form-control-sm" value="30" min="1" max="730">
                            </div>
                            <div class="col-md-6">
                                <label for="diasBlock" class="form-label fw-bold small">Retener BLOCK (días):</label>
                                <input type="number" id="diasBlock" class="form-control form-control-sm" value="90" min="7" max="1095">
                            </div>
                        </div>
                    </div>
                    <div class="d-flex gap-2">
                        <button type="button" class="btn btn-outline-primary w-50" id="btnLimpiarPassAntiguo">
                            <i class="bi bi-eraser me-1"></i> Limpiar PASS Antiguos
                        </button>
                        <button type="button" class="btn btn-outline-danger w-50" id="btnLimpiarBlockAntiguo">
                            <i class="bi bi-shield-x me-1"></i> Limpiar BLOCK Antiguos
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    let enEjecucion = false;

    async function ejecutarLimpiezaPorLotes(tipo, etiqueta) {
        if (enEjecucion) return;
        enEjecucion = true;

        const panelProgreso = document.getElementById('panelProgreso');
        const textoProgreso = document.getElementById('textoProgreso');
        const contadorEl    = document.getElementById('contadorEliminados');
        const barra         = document.getElementById('barraProgreso');

        panelProgreso.classList.remove('d-none');
        barra.className = 'progress-bar progress-bar-striped progress-bar-animated bg-warning text-dark fw-bold';
        barra.textContent = 'Procesando lotes de 25,000 filas...';
        textoProgreso.innerHTML = `<span class="spinner-border spinner-border-sm text-warning me-2"></span>${etiqueta}...`;

        let totalEliminados = 0;
        let continuar = true;
        let ultimoMensaje = '';

        const diasAuditado = document.getElementById('diasAuditado').value;
        const diasPass     = document.getElementById('diasPass').value;
        const diasBlock    = document.getElementById('diasBlock').value;

        try {
            while (continuar) {
                const formData = new FormData();
                formData.append('ajax_limpiar', '1');
                formData.append('tipo', tipo);
                formData.append('dias_auditado', diasAuditado);
                formData.append('dias_pass', diasPass);
                formData.append('dias_block', diasBlock);

                const resp = await fetch('mantenimiento_bd.php', {
                    method: 'POST',
                    body: formData
                });
                const rawText = await resp.text();
                let data;
                try {
                    data = JSON.parse(rawText);
                } catch (parseErr) {
                    throw new Error('Respuesta inesperada del servidor: ' + rawText.replace(/<[^>]*>/g, ' ').trim().slice(0, 220));
                }

                if (!data.ok) {
                    throw new Error(data.error || 'Error desconocido en el servidor.');
                }

                totalEliminados += (data.eliminados || 0);
                contadorEl.textContent = `${totalEliminados.toLocaleString()} registros eliminados`;
                continuar = Boolean(data.continuar);
                if (data.mensaje) ultimoMensaje = data.mensaje;
            }

            barra.className = 'progress-bar bg-success text-white fw-bold';
            barra.textContent = 'Proceso completado';
            const msgFinal = ultimoMensaje || 'Limpieza finalizada correctamente. Recargando estadísticas...';
            textoProgreso.innerHTML = `<i class="bi bi-check-circle-fill text-success me-2"></i>${msgFinal}`;

            setTimeout(() => window.location.reload(), 2000);
        } catch (err) {
            barra.className = 'progress-bar bg-danger text-white fw-bold';
            barra.textContent = 'Error';
            textoProgreso.innerHTML = `<i class="bi bi-exclamation-triangle-fill text-danger me-2"></i>Error: ${err.message}`;
            enEjecucion = false;
        }
    }

    document.getElementById('btnLimpiarAuditados').addEventListener('click', function() {
        const dias = document.getElementById('diasAuditado').value;
        if (confirm(`¿Eliminar todos los eventos PASS hacia IPs ya auditadas (confiables) con más de ${dias} día(s) de antigüedad?`)) {
            ejecutarLimpiezaPorLotes('auditados_confiables', 'Eliminando registros ya auditados');
        }
    });

    document.getElementById('btnLimpiarPassAntiguo').addEventListener('click', function() {
        const dias = document.getElementById('diasPass').value;
        if (confirm(`¿Eliminar todos los registros PASS con más de ${dias} días de antigüedad?`)) {
            ejecutarLimpiezaPorLotes('historico_pass', 'Depurando historial PASS antiguo');
        }
    });

    document.getElementById('btnLimpiarBlockAntiguo').addEventListener('click', function() {
        const dias = document.getElementById('diasBlock').value;
        if (confirm(`¿Eliminar todos los registros BLOCK con más de ${dias} días de antigüedad?`)) {
            ejecutarLimpiezaPorLotes('historico_block', 'Depurando historial BLOCK antiguo');
        }
    });

    document.getElementById('btnOptimizarTabla').addEventListener('click', function() {
        if (confirm('¿Ejecutar OPTIMIZE TABLE sobre firewall_eventos para desfragmentar y liberar espacio en disco?')) {
            ejecutarLimpiezaPorLotes('optimizar_tabla', 'Optimizando tabla firewall_eventos');
        }
    });
});
</script>

<?php include 'views/footer.php'; ?>