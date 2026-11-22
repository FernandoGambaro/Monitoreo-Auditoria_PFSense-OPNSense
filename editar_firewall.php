<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;
use App\Encryption;

$db = (new Database())->getConnection();
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
$mensaje = '';
$tipoAlerta = '';

if (!$id && !isset($_POST['id'])) {
    header('Location: firewalls.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Tomamos el ID del firewall de manera segura directamente desde la URL (GET)
    $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
    if (!$id) {
        $id = (int) ($_POST['id'] ?? 0);
    }

    if ($id <= 0) {
        $mensaje = 'ID de firewall inválido.';
        $tipoAlerta = 'danger';
    } else {
        // 1. Si la acción es agregar una red interna
        if (isset($_POST['accion']) && $_POST['accion'] === 'agregar_red') {
            $nombreRed = trim($_POST['nombre_red'] ?? '');
            $tipoRed = trim($_POST['tipo_red'] ?? 'LAN');
            $rangoCidr = trim($_POST['rango_cidr'] ?? '');

            if (!empty($nombreRed) && !empty($rangoCidr)) {
                try {
                    $stmtRed = $db->prepare("INSERT INTO firewall_redes (firewall_id, nombre, tipo, rango_cidr) VALUES (?, ?, ?, ?)");
                    $stmtRedes->execute([$id, $nombreRed, $tipoRed, $rangoCidr]);
                    $mensaje = 'Red interna / VLAN agregada exitosamente.';
                    $tipoAlerta = 'success';
                } catch (\Exception $e) {
                    $mensaje = 'Error al agregar la red: ' . $e->getMessage();
                    $tipoAlerta = 'danger';
                }
            } else {
                $mensaje = 'El nombre de la red y el rango CIDR son obligatorios.';
                $tipoAlerta = 'danger';
            }
        }
        // 2. Si la acción es eliminar una red interna
        elseif (isset($_POST['accion']) && $_POST['accion'] === 'eliminar_red') {
            $redId = (int) ($_POST['red_id'] ?? 0);

            if ($redId > 0) {
                try {
                    $stmtDel = $db->prepare("DELETE FROM firewall_redes WHERE id = ? AND firewall_id = ?");
                    $stmtDel->execute([$redId, $id]);

                    $mensaje = 'Red interna eliminada correctamente.';
                    $tipoAlerta = 'success';
                } catch (\Exception $e) {
                    $mensaje = 'Error al eliminar la red: ' . $e->getMessage();
                    $tipoAlerta = 'danger';
                }
            } else {
                $mensaje = 'Identificador de red inválido.';
                $tipoAlerta = 'danger';
            }
        }
        // 3. Actualización de datos generales del Firewall
        else {
            $nombre = trim($_POST['nombre'] ?? '');
            $tipo = $_POST['tipo'] ?? 'opnsense';
            $ip = trim($_POST['ip'] ?? '');
            $puerto = (int) ($_POST['puerto_ssh'] ?? 22);
            $usuario = trim($_POST['usuario_ssh'] ?? 'root');
            $passwordPlana = $_POST['password_ssh'] ?? '';
            $activo = isset($_POST['activo']) ? 1 : 0;

            if (empty($nombre) || empty($ip)) {
                $mensaje = 'El nombre y la dirección IP son obligatorios.';
                $tipoAlerta = 'danger';
            } else {
                try {
                    if (!empty($passwordPlana)) {
                        $encryption = new Encryption();
                        $passwordCifrada = $encryption->encode($passwordPlana);

                        $stmt = $db->prepare("
                            UPDATE firewalls 
                            SET nombre = ?, tipo = ?, ip = ?, puerto_ssh = ?, usuario_ssh = ?, password_ssh = ?, activo = ?
                            WHERE id = ?
                        ");
                        $stmt->execute([$nombre, $tipo, $ip, $puerto, $usuario, $passwordCifrada, $activo, $id]);
                    } else {
                        $stmt = $db->prepare("
                            UPDATE firewalls 
                            SET nombre = ?, tipo = ?, ip = ?, puerto_ssh = ?, usuario_ssh = ?, activo = ?
                            WHERE id = ?
                        ");
                        $stmt->execute([$nombre, $tipo, $ip, $puerto, $usuario, $activo, $id]);
                    }

                    $mensaje = 'Configuración del firewall actualizada correctamente.';
                    $tipoAlerta = 'success';
                } catch (\Exception $e) {
                    $mensaje = 'Error al actualizar: ' . $e->getMessage();
                    $tipoAlerta = 'danger';
                }
            }
        }
    }
}

// Obtener datos actuales del firewall
$stmt = $db->prepare("SELECT * FROM firewalls WHERE id = ?");
$stmt->execute([$id]);
$fw = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$fw) {
    header('Location: firewalls.php');
    exit;
}

// Obtener redes asociadas a este firewall
$stmtRedes = $db->prepare("SELECT * FROM firewall_redes WHERE firewall_id = ? ORDER BY id ASC");
$stmtRedes->execute([$id]);
$redes = $stmtRedes->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-4 mb-5">
    <div class="row justify-content-center">
        <div class="col-md-9">
            
            <?php if (!empty($mensaje)): ?>
                <div class="alert alert-<?= $tipoAlerta ?> alert-dismissible fade show" role="alert">
                    <?= htmlspecialchars($mensaje) ?>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
            <?php endif; ?>

            <!-- Tarjeta 1: Edición General del Firewall -->
            <div class="card shadow mb-4">
                <div class="card-header bg-primary text-white d-flex align-items-center gap-2">
                    <i class="bi bi-pencil-square fs-4"></i>
                    <h5 class="mb-0">Editar Firewall: <?= htmlspecialchars($fw['nombre']) ?></h5>
                </div>
                <div class="card-body p-4">
                    <form method="POST" action="editar_firewall.php?id=<?= $fw['id'] ?>">
                        <input type="hidden" name="id" value="<?= $fw['id'] ?>">

                        <div class="mb-3">
                            <label for="nombre" class="form-label fw-bold">Nombre Identificativo</label>
                            <input type="text" class="form-control" id="nombre" name="nombre" value="<?= htmlspecialchars($fw['nombre']) ?>" required>
                        </div>

                        <div class="mb-3">
                            <label for="tipo" class="form-label fw-bold">Tipo de Firewall</label>
                            <select class="form-select" id="tipo" name="tipo" required>
                                <option value="opnsense" <?= $fw['tipo'] === 'opnsense' ? 'selected' : '' ?>>OPNsense</option>
                                <option value="pfsense" <?= $fw['tipo'] === 'pfsense' ? 'selected' : '' ?>>pfSense</option>
                            </select>
                        </div>

                        <div class="mb-3">
                            <label for="ip" class="form-label fw-bold">Dirección IP o Host</label>
                            <input type="text" class="form-control" id="ip" name="ip" value="<?= htmlspecialchars($fw['ip']) ?>" required>
                        </div>

                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label for="puerto_ssh" class="form-label fw-bold">Puerto SSH</label>
                                <input type="number" class="form-control" id="puerto_ssh" name="puerto_ssh" value="<?= $fw['puerto_ssh'] ?>" required>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label for="usuario_ssh" class="form-label fw-bold">Usuario SSH</label>
                                <input type="text" class="form-control" id="usuario_ssh" name="usuario_ssh" value="<?= htmlspecialchars($fw['usuario_ssh']) ?>" required>
                            </div>
                        </div>

                        <div class="mb-3">
                            <label for="password_ssh" class="form-label fw-bold">Contraseña SSH (Nueva)</label>
                            <input type="password" class="form-control" id="password_ssh" name="password_ssh" placeholder="Dejar en blanco para conservar la actual">
                            <div class="form-text">Solo completa este campo si deseas cambiar la contraseña de acceso SSH.</div>
                        </div>

                        <div class="mb-4 form-check">
                            <input type="checkbox" class="form-check-input" id="activo" name="activo" value="1" <?= $fw['activo'] ? 'checked' : '' ?>>
                            <label class="form-check-label fw-bold" for="activo">Firewall Activo (Monitoreo habilitado)</label>
                        </div>

                        <div class="d-flex justify-content-between">
                            <a href="firewalls.php" class="btn btn-secondary">
                                <i class="bi bi-arrow-left me-1"></i> Volver al Listado
                            </a>
                            <button type="submit" class="btn btn-success">
                                <i class="bi bi-save me-1"></i> Guardar Cambios Generales
                            </button>
                        </div>
                    </form>
                </div>
            </div>

            <!-- Tarjeta 2: Configuración de Redes Internas / VLANs -->
            <div class="card shadow">
                <div class="card-header bg-dark text-white d-flex align-items-center gap-2">
                    <i class="bi bi-diagram-3 fs-4"></i>
                    <h5 class="mb-0">Redes Internas y VLANs asociadas</h5>
                </div>
                <div class="card-body p-4">
                    <p class="text-muted">
                        Define aquí los rangos de red locales o VLANs detrás de este firewall. Al importar los registros (*logs*), cualquier IP de origen que pertenezca a estos rangos será etiquetada con el nombre de su red respectiva en lugar de aparecer como "DESCONOCIDO".
                    </p>

                    <!-- Listado de redes existentes -->
                    <div class="table-responsive mb-4">
                        <table class="table table-bordered table-sm align-middle">
                            <thead class="table-light">
                                <tr>
                                    <th>Nombre de Red</th>
                                    <th>Tipo</th>
                                    <th>Rango CIDR</th>
                                    <th class="text-center" style="width: 100px;">Acción</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php if (empty($redes)): ?>
                                    <tr>
                                        <td colspan="4" class="text-center text-muted py-3">No hay redes internas o VLANs configuradas. (Se usará la subred base de la IP del firewall por defecto).</td>
                                    </tr>
                                <?php else: ?>
                                    <?php foreach ($redes as $red): ?>
                                        <tr>
                                            <td class="fw-bold"><?= htmlspecialchars($red['nombre']) ?></td>
                                            <td><span class="badge bg-secondary"><?= htmlspecialchars($red['tipo']) ?></span></td>
                                            <td><code><?= htmlspecialchars($red['rango_cidr']) ?></code></td>
                                            <td class="text-center">
                                                <form method="POST" action="editar_firewall.php?id=<?= $fw['id'] ?>" onsubmit="return confirm('¿Desea eliminar esta red?');" style="display:inline;">
                                                    <input type="hidden" name="accion" value="eliminar_red">
                                                    <input type="hidden" name="red_id" value="<?= $red['id'] ?>">
                                                    <button type="submit" class="btn btn-sm btn-outline-danger" title="Eliminar red">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>

                    <!-- Formulario para agregar nueva red -->
                    <form method="POST" action="editar_firewall.php?id=<?= $fw['id'] ?>" class="row g-3 bg-light p-3 rounded border">
                        <input type="hidden" name="accion" value="agregar_red">
                        <input type="hidden" name="id" value="<?= $fw['id'] ?>">
                        
                        <h6 class="fw-bold text-primary mb-1"><i class="bi bi-plus-circle me-1"></i> Añadir Nueva Red / VLAN</h6>
                        
                        <div class="col-md-5">
                            <label for="nombre_red" class="form-label small fw-bold">Nombre descriptivo</label>
                            <input type="text" class="form-control form-control-sm" id="nombre_red" name="nombre_red" placeholder="Ej. Red LAN Principal" required>
                        </div>
                        <div class="col-md-3">
                            <label for="tipo_red" class="form-label small fw-bold">Tipo</label>
                            <select class="form-select form-select-sm" id="tipo_red" name="tipo_red">
                                <option value="LAN">LAN</option>
                                <option value="VLAN">VLAN</option>
                                <option value="WIFI">WIFI</option>
                                <option value="DMZ">DMZ</option>
                                <option value="OTRO">OTRO</option>
                            </select>
                        </div>
                        <div class="col-md-4">
                            <label for="rango_cidr" class="form-label small fw-bold">Rango CIDR</label>
                            <div class="input-group input-group-sm">
                                <input type="text" class="form-control" id="rango_cidr" name="rango_cidr" placeholder="192.168.10.0/24" required>
                                <button type="submit" class="btn btn-primary"><i class="bi bi-check-lg"></i> Agregar</button>
                            </div>
                        </div>
                    </form>

                </div>
            </div>

        </div>
    </div>
</div>

<?php include 'views/footer.php'; ?>