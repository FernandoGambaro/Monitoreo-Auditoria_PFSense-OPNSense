<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

function cargarEnv($filePath) {
    if (!file_exists($filePath)) return;
    $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || strpos($line, '#') === 0) continue;
        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name); $value = trim($value);
            if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value; $_SERVER[$name] = $value;
            }
        }
    }
}
cargarEnv(__DIR__ . '/.env');

require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

$db = new Database();
$pdo = $db->getConnection();

// Endpoint AJAX para obtener el historial detallado de puertos de una IP
if (isset($_GET['ajax']) && $_GET['ajax'] === 'historial_ip') {
    header('Content-Type: application/json');
    $ip = $_GET['ip'] ?? '';
    $firewallId = (int) ($_GET['firewall_id'] ?? 0);

    if (empty($ip) || $firewallId <= 0) {
        echo json_encode([]);
        exit;
    }

    $stmt = $pdo->prepare("
        SELECT fecha_evento, puerto_destino, accion, protocolo 
        FROM firewall_eventos 
        WHERE firewall_id = ? AND ip_origen = ? 
        ORDER BY fecha_evento DESC 
        LIMIT 150
    ");
    $stmt->execute([$firewallId, $ip]);
    $eventos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode($eventos);
    exit;
}

// Procesar acciones por POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $accion = $_POST['accion'] ?? '';

    if ($accion === 'probar_mail') {
        $emailDestino = getenv('ALERT_EMAIL_DESTINO');
        
        if (empty($emailDestino)) {
            $_SESSION['msg_texto'] = 'El destino del correo (ALERT_EMAIL_DESTINO) no está configurado en el archivo .env.';
            $_SESSION['msg_tipo'] = 'danger';
        } else {
            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host       = getenv('SMTP_HOST');
                $mail->SMTPAuth   = true;
                $mail->Username   = getenv('SMTP_USER');
                $mail->Password   = getenv('SMTP_PASS');
                $mail->SMTPSecure = 'ssl';
                $mail->Port       = (int) (getenv('SMTP_PORT') ?: 465);
                $mail->Timeout    = 5; 
                $mail->CharSet    = 'UTF-8';

                $mail->setFrom(getenv('SMTP_USER'), 'Firewall Monitor Test');
                $mail->addAddress($emailDestino);

                $mail->isHTML(false);
                $mail->Subject = "[PRUEBA SMTP] Alerta de Firewall - Configuración Exitosa";
                $mail->Body    = "Hola,\n\nEste es un correo de prueba enviado desde el sistema de monitoreo de firewalls para verificar que la conexión SMTP funciona correctamente.\n\n¡Configuración exitosa!";

                $mail->send();
                $_SESSION['msg_texto'] = '¡Correo de prueba enviado con éxito a ' . htmlspecialchars($emailDestino) . '!';
                $_SESSION['msg_tipo'] = 'success';
            } catch (Exception $e) {
                $_SESSION['msg_texto'] = 'Error al conectar con el servidor SMTP: ' . htmlspecialchars($mail->ErrorInfo);
                $_SESSION['msg_tipo'] = 'danger';
            }
        }
    }

    if ($accion === 'marcar_leida') {
        $alertaId = (int) ($_POST['alerta_id'] ?? 0);
        if ($alertaId > 0) {
            $stmt = $pdo->prepare("UPDATE firewall_alertas SET leida = 1 WHERE id = ?");
            $stmt->execute([$alertaId]);
            $_SESSION['msg_texto'] = 'Alerta marcada como leída.';
            $_SESSION['msg_tipo'] = 'success';
        }
    }

    if ($accion === 'marcar_todas_leidas') {
        $pdo->query("UPDATE firewall_alertas SET leida = 1");
        $_SESSION['msg_texto'] = 'Todas las alertas han sido marcadas como leídas.';
        $_SESSION['msg_tipo'] = 'success';
    }

    header('Location: alertas.php');
    exit;
}

$mensaje = $_SESSION['msg_texto'] ?? '';
$tipoAlerta = $_SESSION['msg_tipo'] ?? '';
unset($_SESSION['msg_texto'], $_SESSION['msg_tipo']);

// Configuración de Paginación
$porPagina = 10;
$paginaActual = isset($_GET['pagina']) ? max(1, (int) $_GET['pagina']) : 1;
$offset = ($paginaActual - 1) * $porPagina;

// Contar total de alertas para la paginación
$totalAlertasStmt = $pdo->query("SELECT COUNT(*) FROM firewall_alertas");
$totalAlertas = $totalAlertasStmt->fetchColumn();
$totalPaginas = ceil($totalAlertas / $porPagina);

// Obtener alertas paginadas
$stmt = $pdo->prepare("
    SELECT a.*, f.nombre AS firewall_nombre 
    FROM firewall_alertas a
    JOIN firewalls f ON a.firewall_id = f.id
    ORDER BY a.fecha_alerta DESC
    LIMIT ? OFFSET ?
");
$stmt->bindValue(1, $porPagina, PDO::PARAM_INT);
$stmt->bindValue(2, $offset, PDO::PARAM_INT);
$stmt->execute();
$alertas = $stmt->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-4 mb-5">
    
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-shield-exclamation text-warning me-2"></i>Gestión de Alertas de Seguridad</h2>
        
        <form method="POST" action="alertas.php" class="m-0">
            <input type="hidden" name="accion" value="probar_mail">
            <button type="submit" class="btn btn-outline-primary">
                <i class="bi bi-envelope-check me-1"></i> Probar Envío de Mail
            </button>
        </form>
    </div>

    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= htmlspecialchars($tipoAlerta) ?> alert-dismissible fade show shadow-sm" role="alert">
            <?= htmlspecialchars($mensaje) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <div class="card shadow-sm mb-4 bg-light">
        <div class="card-body py-2 px-3 small text-muted d-flex justify-content-between align-items-center">
            <div>
                <strong>Destinatario de Alertas (.env):</strong> <code><?= htmlspecialchars(getenv('ALERT_EMAIL_DESTINO') ?: 'No configurado') ?></code> | 
                <strong>Servidor SMTP:</strong> <code><?= htmlspecialchars(getenv('SMTP_HOST') ?: 'No configurado') ?>:<?= htmlspecialchars(getenv('SMTP_PORT') ?: '465') ?></code>
            </div>
            <span class="text-secondary">Haz clic sobre cualquier dirección IP en los mensajes para ver el historial detallado de puertos.</span>
        </div>
    </div>

    <div class="card shadow">
        <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
            <h5 class="mb-0"><i class="bi bi-list-nested me-2"></i>Historial de Alertas Generadas (Total: <?= $totalAlertas ?>)</h5>
            <?php if (!empty($alertas)): ?>
                <form method="POST" action="alertas.php" class="m-0">
                    <input type="hidden" name="accion" value="marcar_todas_leidas">
                    <button type="submit" class="btn btn-sm btn-outline-light">Marcar todas como leídas</button>
                </form>
            <?php endif; ?>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped table-hover align-middle">
                    <thead class="table-secondary">
                        <tr>
                            <th>Fecha / Hora</th>
                            <th>Firewall</th>
                            <th>Tipo de Alerta</th>
                            <th>Nivel</th>
                            <th>Mensaje / Detalle</th>
                            <th>Estado</th>
                            <th class="text-end">Acción</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($alertas)): ?>
                            <tr>
                                <td colspan="7" class="text-center text-muted py-4">No hay alertas de seguridad registradas en este momento.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($alertas as $alt): ?>
                                <?php 
                                    $badgeNivel = match($alt['nivel_riesgo']) {
                                        'CRITICO' => 'bg-danger',
                                        'ALTO' => 'bg-warning text-dark',
                                        default => 'bg-secondary'
                                    };

                                    $ip = $alt['ip_origen'];
                                    $fwId = $alt['firewall_id'];
                                    $mensajeHtml = htmlspecialchars($alt['mensaje']);
                                    if (!empty($ip)) {
                                        $enlaceIp = '<a href="#" class="text-primary fw-bold text-decoration-underline abrir-modal-ip" data-ip="' . htmlspecialchars($ip) . '" data-firewall-id="' . $fwId . '" title="Ver historial de puertos"><i class="bi bi-search"></i> ' . htmlspecialchars($ip) . '</a>';
                                        $mensajeHtml = str_replace($ip, $enlaceIp, $mensajeHtml);
                                    }
                                ?>
                                <tr>
                                    <td><?= htmlspecialchars($alt['fecha_evento'] ?? $alt['fecha_alerta']) ?></td>
                                    <td class="fw-bold"><?= htmlspecialchars($alt['firewall_nombre']) ?></td>
                                    <td><code><?= htmlspecialchars($alt['tipo_alerta']) ?></code></td>
                                    <td><span class="badge <?= $badgeNivel ?>"><?= htmlspecialchars($alt['nivel_riesgo']) ?></span></td>
                                    <td>
                                        <?= $mensajeHtml ?>
                                        <?php if (!empty($alt['ip_origen'])): ?>
                                            <br><a href="https://www.virustotal.com/gui/ip-address/<?= htmlspecialchars($alt['ip_origen']) ?>" target="_blank" class="small text-danger text-decoration-none">
                                                <i class="bi bi-box-arrow-up-right"></i> Ver IP en VirusTotal
                                            </a>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <?php if ($alt['leida']): ?>
                                            <span class="badge bg-success">Leída</span>
                                        <?php else: ?>
                                            <span class="badge bg-primary">Nueva</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="text-end">
                                        <?php if (!$alt['leida']): ?>
                                            <form method="POST" action="alertas.php" class="d-inline">
                                                <input type="hidden" name="accion" value="marcar_leida">
                                                <input type="hidden" name="alerta_id" value="<?= $alt['id'] ?>">
                                                <button type="submit" class="btn btn-sm btn-outline-success" title="Marcar como leída">
                                                    <i class="bi bi-check-lg"></i>
                                                </button>
                                            </form>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>

            <!-- Controles de Paginación -->
            <?php if ($totalPaginas > 1): ?>
                <nav aria-label="Navegación de paginación" class="mt-4">
                    <ul class="pagination justify-content-center mb-0">
                        <li class="page-item <?= ($paginaActual <= 1) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?pagina=<?= $paginaActual - 1 ?>" tabindex="-1">Anterior</a>
                        </li>

                        <?php for ($i = 1; $i <= $totalPaginas; $i++): ?>
                            <li class="page-item <?= ($paginaActual == $i) ? 'active' : '' ?>">
                                <a class="page-link" href="?pagina=<?= $i ?>"><?= $i ?></a>
                            </li>
                        <?php endfor; ?>

                        <li class="page-item <?= ($paginaActual >= $totalPaginas) ? 'disabled' : '' ?>">
                            <a class="page-link" href="?pagina=<?= $paginaActual + 1 ?>">Siguiente</a>
                        </li>
                    </ul>
                </nav>
            <?php endif; ?>

        </div>
    </div>
</div>

<!-- Modal para ver el historial de intentos/puertos de la IP -->
<div class="modal fade" id="modalHistorialIp" tabindex="-1" aria-labelledby="modalHistorialIpLabel" aria-hidden="true">
  <div class="modal-dialog modal-lg modal-dialog-scrollable">
    <div class="modal-content">
      <div class="modal-header bg-dark text-white">
        <h5 class="modal-title" id="modalHistorialIpLabel">
            <i class="bi bi-globe me-2"></i>Historial de Intentos para la IP: <span id="spanIpModal" class="text-warning"></span>
        </h5>
        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
      </div>
      <div class="modal-body">
        <div id="modalLoading" class="text-center py-4">
            <div class="spinner-border text-primary" role="status">
                <span class="visually-hidden">Cargando...</span>
            </div>
            <p class="text-muted mt-2">Consultando registros del firewall...</p>
        </div>
        <div id="modalContentContainer" style="display: none;">
            <div class="table-responsive">
                <table class="table table-sm table-striped table-hover align-middle">
                    <thead class="table-dark">
                        <tr>
                            <th>Fecha y Hora</th>
                            <th>Puerto Destino</th>
                            <th>Protocolo</th>
                            <th>Acción</th>
                        </tr>
                    </thead>
                    <tbody id="tablaHistorialBody">
                        <!-- Rellenado dinámicamente mediante JS -->
                    </tbody>
                </table>
            </div>
        </div>
        <div id="modalEmpty" class="text-center text-muted py-4" style="display: none;">
            No se encontraron registros de eventos para esta IP en el firewall seleccionado.
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cerrar</button>
      </div>
    </div>
  </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    const modalElement = document.getElementById('modalHistorialIp');
    const modal = new bootstrap.Modal(modalElement);
    const spanIpModal = document.getElementById('spanIpModal');
    const modalLoading = document.getElementById('modalLoading');
    const modalContentContainer = document.getElementById('modalContentContainer');
    const modalEmpty = document.getElementById('modalEmpty');
    const tablaHistorialBody = document.getElementById('tablaHistorialBody');

    document.querySelectorAll('.abrir-modal-ip').forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            const ip = this.getAttribute('data-ip');
            const firewallId = this.getAttribute('data-firewall-id');

            spanIpModal.textContent = ip;
            modalLoading.style.display = 'block';
            modalContentContainer.style.display = 'none';
            modalEmpty.style.display = 'none';
            tablaHistorialBody.innerHTML = '';

            modal.show();

            fetch(`alertas.php?ajax=historial_ip&ip=${encodeURIComponent(ip)}&firewall_id=${firewallId}`)
                .then(response => response.json())
                .then(data => {
                    modalLoading.style.display = 'none';
                    if (data && data.length > 0) {
                        data.forEach(evt => {
                            let badgeAccion = 'bg-secondary';
                            const accionLower = (evt.accion || '').toLowerCase();
                            if (accionLower === 'pass' || accionLower === 'permit') {
                                badgeAccion = 'bg-success';
                            } else if (accionLower === 'block' || accionLower === 'drop') {
                                badgeAccion = 'bg-danger';
                            }

                            const tr = document.createElement('tr');
                            tr.innerHTML = `
                                <td>${evt.fecha_evento}</td>
                                <td><span class="badge bg-light text-dark fw-bold border">${evt.puerto_destino}</span></td>
                                <td>${evt.protocolo || 'N/A'}</td>
                                <td><span class="badge ${badgeAccion}">${evt.accion.toUpperCase()}</span></td>
                            `;
                            tablaHistorialBody.appendChild(tr);
                        });
                        modalContentContainer.style.display = 'block';
                    } else {
                        modalEmpty.style.display = 'block';
                    }
                })
                .catch(error => {
                    modalLoading.style.display = 'none';
                    modalEmpty.textContent = 'Error al cargar los datos de la IP.';
                    modalEmpty.style.display = 'block';
                    console.error('Error:', error);
                });
        });
    });
});
</script>

<?php include 'views/footer.php'; ?>