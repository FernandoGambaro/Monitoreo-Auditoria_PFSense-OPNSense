<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/bootstrap.php';

use Firewall\Database;

$db = (new Database())->getConnection();

// Obtener listado de firewalls activos para el selector
$stmt = $db->query("SELECT id, nombre, tipo, ip FROM firewalls WHERE activo = 1 ORDER BY nombre ASC");
$firewalls = $stmt->fetchAll(PDO::FETCH_ASSOC);

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-4">
    <div class="row justify-content-center">
        <div class="col-md-8 col-lg-6">
            
            <!-- Mostrar mensajes de éxito o error guardados en sesión -->
            <?php if (isset($_SESSION['msg_texto'])): ?>
                <div class="alert alert-<?= htmlspecialchars($_SESSION['msg_tipo'] ?? 'info') ?> alert-dismissible fade show shadow-sm" role="alert">
                    <div class="d-flex align-items-center">
                        <?php if (($_SESSION['msg_tipo'] ?? '') === 'success'): ?>
                            <i class="bi bi-check-circle-fill fs-4 me-2"></i>
                        <?php else: ?>
                            <i class="bi bi-exclamation-triangle-fill fs-4 me-2"></i>
                        <?php endif; ?>
                        <div>
                            <?= htmlspecialchars($_SESSION['msg_texto']) ?>
                        </div>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                </div>
                <?php unset($_SESSION['msg_tipo'], $_SESSION['msg_texto']); ?>
            <?php endif; ?>

            <div class="card shadow">
                <div class="card-header bg-primary text-white d-flex align-items-center gap-2">
                    <i class="bi bi-cloud-arrow-down fs-4"></i>
                    <h5 class="mb-0">Importar Logs de Firewall por SSH</h5>
                </div>
                <div class="card-body p-4">
                    <p class="text-muted">
                        Selecciona el dispositivo perimetral y la cantidad de líneas de registro que deseas sincronizar desde el servidor remoto.
                    </p>

                    <form method="POST" action="process_firewall_import.php" class="needs-validation" novalidate>
                        
                        <div class="mb-3">
                            <label for="firewall_id" class="form-label fw-bold">Dispositivo Firewall</label>
                            <select name="firewall_id" id="firewall_id" class="form-select" required>
                                <option value="">-- Seleccione un firewall --</option>
                                <?php foreach ($firewalls as $fw): ?>
                                    <option value="<?= $fw['id'] ?>" data-tipo="<?= htmlspecialchars($fw['tipo']) ?>">
                                        <?= htmlspecialchars($fw['nombre']) ?> (<?= htmlspecialchars($fw['ip']) ?>) [<?= strtoupper($fw['tipo']) ?>]
                                    </option>
                                <?php endforeach; ?>
                            </select>
                            <div class="invalid-feedback">Por favor seleccione un firewall.</div>
                        </div>

                        <!-- Campo oculto que se actualiza automáticamente según el firewall seleccionado -->
                        <input type="hidden" name="tipo_firewall" id="tipo_firewall" value="opnsense">

                        <div class="mb-4">
                            <label for="cantidad" class="form-label fw-bold">Cantidad de líneas (*tail*)</label>
                            <input type="number" name="cantidad" id="cantidad" class="form-control" value="1000" min="100" max="10000" required>
                            <div class="form-text">Número de registros recientes a extraer del archivo de log remoto.</div>
                        </div>

                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-success btn-lg">
                                <i class="bi bi-play-fill me-1"></i> Iniciar Importación
                            </button>
                            <a href="dashboard.php" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left me-1"></i> Volver al Dashboard
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
// Script para actualizar dinámicamente el tipo de firewall oculto al cambiar la selección
document.getElementById('firewall_id').addEventListener('change', function() {
    var selectedOption = this.options[this.selectedIndex];
    var tipo = selectedOption.getAttribute('data-tipo');
    if (tipo) {
        document.getElementById('tipo_firewall').value = tipo;
    }
});
</script>

<?php include 'views/footer.php'; ?>