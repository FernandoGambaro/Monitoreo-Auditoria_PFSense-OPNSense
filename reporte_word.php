<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Cargar el archivo centralizador de la raíz
require_once __DIR__ . '/bootstrap.php';

// Si generar_informe.php está dentro de la carpeta reportes/
require_once __DIR__ . '/reportes/generar_informe.php';

use Firewall\Database;
use Firewall\ReportGenerator;

$db = new Database();
$pdo = $db->getConnection();

$mensajeError = '';

// Procesar la solicitud cuando el usuario envía el formulario
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fechaInicio = $_POST['fecha_inicio'] ?? date('Y-m-01');
    $fechaFin = $_POST['fecha_fin'] ?? date('Y-m-t');

    // Validación básica de fechas
    if ($fechaInicio > $fechaFin) {
        $mensajeError = 'La fecha de inicio no puede ser posterior a la fecha de fin.';
    } else {
        try {

            $dirInformes = __DIR__ . '/../tmp';
            if (!is_dir($dirInformes)) {
                mkdir($dirInformes, 0755, true);
            }


            $nombreArchivo = 'informe_ejecutivo_' . date('Ymd', strtotime($fechaInicio)) . '_a_' . date('Ymd', strtotime($fechaFin)) . '.docx';
            $rutaCompleta = $dirInformes . '/' . $nombreArchivo;

            // Generar el archivo mediante la clase
            $generator = new ReportGenerator($pdo);
            $generator->generarMensual($rutaCompleta, $fechaInicio, $fechaFin);

            if (file_exists($rutaCompleta)) {
                // Limpiar cualquier salida previa en el buffer para evitar corrupción de binarios
                if (ob_get_level()) {
                    ob_end_clean();
                }

                header('Content-Description: File Transfer');
                header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
                header('Content-Disposition: attachment; filename="' . basename($rutaCompleta) . '"');
                header('Expires: 0');
                header('Cache-Control: must-revalidate');
                header('Pragma: public');
                header('Content-Length: ' . filesize($rutaCompleta));

                readfile($rutaCompleta);
                exit;
            }
        } catch (Exception $e) {
            $mensajeError = 'Error al generar el informe: ' . htmlspecialchars($e->getMessage());
        }
    }
}

// Valores por defecto para los inputs del formulario (Mes actual)
$defInicio = date('Y-m-01');
$defFin = date('Y-m-t');

include 'views/header.php';
include 'views/menu.php';
?>

<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-8 col-lg-6">
            <div class="card shadow">
                <div class="card-header bg-primary text-white d-flex align-items-center gap-2">
                    <i class="bi bi-file-earmark-word fs-4"></i>
                    <h5 class="mb-0">Generar Informe Ejecutivo en Word (.docx)</h5>
                </div>
                <div class="card-body p-4">
                    <p class="text-muted">
                        Selecciona el rango de fechas deseado. El sistema procesará las métricas de bloqueo de OPNsense almacenadas en la base de datos y compilará el informe automáticamente.
                    </p>

                    <?php if (!empty($mensajeError)): ?>
                        <div class="alert alert-danger alert-dismissible fade show" role="alert">
                            <i class="bi bi-exclamation-triangle-fill me-2"></i><?= $mensajeError ?>
                            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                        </div>
                    <?php endif; ?>

                    <form method="POST" action="reporte_word.php" class="needs-validation" novalidate>
                        <div class="mb-3">
                            <label for="fecha_inicio" class="form-label fw-bold">Fecha de Inicio</label>
                            <input type="date" class="form-control" id="fecha_inicio" name="fecha_inicio" value="<?= htmlspecialchars($defInicio) ?>" required>
                        </div>

                        <div class="mb-4">
                            <label for="fecha_fin" class="form-label fw-bold">Fecha de Fin</label>
                            <input type="date" class="form-control" id="fecha_fin" name="fecha_fin" value="<?= htmlspecialchars($defFin) ?>" required>
                        </div>

                        <div class="d-grid gap-2">
                            <button type="submit" class="btn btn-success btn-lg">
                                <i class="bi bi-download me-2"></i>Generar y Descargar Informe
                            </button>
                            <a href="dashboard.php" class="btn btn-outline-secondary">
                                <i class="bi bi-arrow-left me-1"></i>Volver al Dashboard
                            </a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<?php include 'views/footer.php'; ?>