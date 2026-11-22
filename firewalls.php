<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;
use App\Encryption;

$db = (new Database())->getConnection();
$mensaje = '';
$tipoAlerta = '';

// Procesar formulario de alta de nuevo Firewall
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['accion']) && $_POST['accion'] === 'crear') {
    $nombre = trim($_POST['nombre'] ?? '');
    $tipo = $_POST['tipo'] ?? 'opnsense';
    $ip = trim($_POST['ip'] ?? '');
    $puerto = (int) ($_POST['puerto_ssh'] ?? 22);
    $usuario = trim($_POST['usuario_ssh'] ?? 'root');
    $passwordPlana = $_POST['password_ssh'] ?? '';

    if (empty($nombre) || empty($ip) || empty($passwordPlana)) {
        $mensaje = 'Por favor, completa los campos obligatorios (Nombre, IP y Contraseña SSH).';
        $tipoAlerta = 'danger';
    } else {
        try {
            $encryption = new Encryption();
            $passwordCifrada = $encryption->encode($passwordPlana);

            $stmt = $db->prepare("
                INSERT INTO firewalls (nombre, tipo, ip, puerto_ssh, usuario_ssh, password_ssh, activo) 
                VALUES (?, ?, ?, ?, ?, ?, 1)
            ");
            $stmt->execute([$nombre, $tipo, $ip, $puerto, $usuario, $passwordCifrada]);

            $mensaje = 'Firewall registrado y credenciales cifradas correctamente.';
            $tipoAlerta = 'success';
        } catch (\Exception $e) {
            $mensaje = 'Error al guardar en la base de datos: ' . $e->getMessage();
            $tipoAlerta = 'danger';
        }
    }
}

// Obtener listado de firewalls registrados
$stmt = $db->query("SELECT * FROM firewalls ORDER BY id DESC");
$firewalls = $stmt->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<?php if (isset($_SESSION['msg_texto'])): ?>
    <div class="alert alert-<?= htmlspecialchars($_SESSION['msg_tipo']) ?> alert-dismissible fade show shadow-sm" role="alert">
        <div class="d-flex align-items-center">
            <?php if ($_SESSION['msg_tipo'] === 'success'): ?>
                <i class="bi bi-check-circle-fill fs-4 me-2"></i>
            <?php else: ?>
                <i class="bi bi-exclamation-triangle-fill fs-4 me-2"></i>
            <?php endif; ?>
            <div><?= htmlspecialchars($_SESSION['msg_texto']) ?></div>
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    </div>
    <?php unset($_SESSION['msg_tipo'], $_SESSION['msg_texto']); ?>
<?php endif; ?>

<div class="container mt-4">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="bi bi-shield-lock me-2"></i>Gestión de Firewalls Perimetrales y Redes</h2>
        <button type="button" class="btn btn-primary" data-bs-toggle="modal" data-bs-target="#modalNuevoFirewall">
            <i class="bi bi-plus-circle me-1"></i> Agregar Firewall
        </button>
    </div>

    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= $tipoAlerta ?> alert-dismissible fade show" role="alert">
            <?= htmlspecialchars($mensaje) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    <?php endif; ?>

    <!-- Tabla de Dispositivos -->
    <div class="card shadow mb-4">
        <div class="card-header bg-dark text-white">
            <h5 class="mb-0"><i class="bi bi-hdd-network me-2"></i>Firewalls Registrados</h5>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-striped table-hover align-middle">
                    <thead class="table-secondary">
                        <tr>
                            <th>ID</th>
                            <th>Nombre</th>
                            <th>Tipo</th>
                            <th>IP</th>
                            <th>Puerto</th>
                            <th>Usuario</th>
                            <th>Estado</th>
                            <th class="text-end">Acciones</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if (empty($firewalls)): ?>
                            <tr>
                                <td colspan="8" class="text-center text-muted py-4">No hay firewalls configurados actualmente.</td>
                            </tr>
                        <?php else: ?>
                            <?php foreach ($firewalls as $fw): ?>
                                <tr>
                                    <td><?= $fw['id'] ?></td>
                                    <td class="fw-bold"><?= htmlspecialchars($fw['nombre']) ?></td>
                                    <td>
                                        <span class="badge bg-<?= $fw['tipo'] === 'pfsense' ? 'warning text-dark' : 'info text-dark' ?>">
                                            <?= strtoupper($fw['tipo']) ?>
                                        </span>
                                    </td>
                                    <td><code><?= htmlspecialchars($fw['ip']) ?></code></td>
                                    <td><?= $fw['puerto_ssh'] ?></td>
                                    <td><?= htmlspecialchars($fw['usuario_ssh']) ?></td>
                                    <td>
                                        <?php if ($fw['activo']): ?>
                                            <span class="badge bg-success">Activo</span>
                                        <?php else: ?>
                                            <span class="badge bg-secondary">Inactivo</span>
                                        <?php endif; ?>
                                    </td>
                                    <td class="text-end">
                                        <a href="test_conexion.php?id=<?= $fw['id'] ?>" class="btn btn-sm btn-outline-info" title="Probar Conexión SSH">
                                            <i class="bi bi-terminal"></i>
                                        </a>
                                        <a href="editar_firewall.php?id=<?= $fw['id'] ?>" class="btn btn-sm btn-outline-primary" title="Editar Firewall y Redes">
                                            <i class="bi bi-pencil-square"></i> Configurar Redes
                                        </a>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<!-- Modal para Nuevo Firewall -->
<div class="modal fade" id="modalNuevoFirewall" tabindex="-1" aria-labelledby="modalNuevoFirewallLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <form method="POST" action="firewalls.php">
                <input type="hidden" name="accion" value="crear">
                <div class="modal-header bg-primary text-white">
                    <h5 class="modal-title" id="modalNuevoFirewallLabel"><i class="bi bi-shield-plus me-2"></i>Registrar Nuevo Firewall</h5>
                    <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <div class="mb-3">
                        <label for="nombre" class="form-label fw-bold">Nombre Identificativo</label>
                        <input type="text" class="form-control" id="nombre" name="nombre" placeholder="Ej. Firewall Sucursal Principal" required>
                    </div>

                    <div class="mb-3">
                        <label for="tipo" class="form-label fw-bold">Tipo de Firewall</label>
                        <select class="form-select" id="tipo" name="tipo" required>
                            <option value="opnsense">OPNsense</option>
                            <option value="pfsense">pfSense</option>
                        </select>
                    </div>

                    <div class="mb-3">
                        <label for="ip" class="form-label fw-bold">Dirección IP o Host</label>
                        <input type="text" class="form-control" id="ip" name="ip" placeholder="192.168.1.1" required>
                    </div>

                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="puerto_ssh" class="form-label fw-bold">Puerto SSH</label>
                            <input type="number" class="form-control" id="puerto_ssh" name="puerto_ssh" value="22" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="usuario_ssh" class="form-label fw-bold">Usuario SSH</label>
                            <input type="text" class="form-control" id="usuario_ssh" name="usuario_ssh" value="root" required>
                        </div>
                    </div>

                    <div class="mb-3">
                        <label for="password_ssh" class="form-label fw-bold">Contraseña SSH</label>
                        <input type="password" class="form-control" id="password_ssh" name="password_ssh" placeholder="Contraseña de acceso" required>
                        <div class="form-text">La contraseña se cifrará de forma segura (AES-256-CBC) antes de ser almacenada.</div>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <button type="submit" class="btn btn-success"><i class="bi bi-save me-1"></i>Guardar Firewall</button>
                </div>
            </form>
        </div>
    </div>
</div>

<?php include 'views/footer.php'; ?>