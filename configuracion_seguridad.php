<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/bootstrap.php';
use Firewall\Database;

$db = new Database();
$pdo = $db->getConnection();

// Catálogo maestro agrupado por región (compatible con nombres y códigos ISO de GeoLite2-Country.mmdb)
$regionesPaises = [
    'Africa' => [
        'AO' => 'Angola', 'BF' => 'Burkina Faso', 'BI' => 'Burundi', 'BJ' => 'Benin',
        'BW' => 'Botswana', 'CD' => 'Congo (DRC)', 'CF' => 'Central African Republic',
        'CG' => 'Congo', 'CI' => "Côte d'Ivoire", 'CM' => 'Cameroon', 'DJ' => 'Djibouti',
        'DZ' => 'Algeria', 'EG' => 'Egypt', 'ER' => 'Eritrea', 'ET' => 'Ethiopia',
        'GA' => 'Gabon', 'GH' => 'Ghana', 'GM' => 'Gambia', 'GN' => 'Guinea',
        'GQ' => 'Equatorial Guinea', 'GW' => 'Guinea-Bissau', 'KE' => 'Kenya', 'KM' => 'Comoros',
        'LR' => 'Liberia', 'LS' => 'Lesotho', 'LY' => 'Libya', 'MA' => 'Morocco',
        'MG' => 'Madagascar', 'ML' => 'Mali', 'MR' => 'Mauritania', 'MU' => 'Mauritius',
        'MW' => 'Malawi', 'MZ' => 'Mozambique', 'NA' => 'Namibia', 'NE' => 'Niger',
        'NG' => 'Nigeria', 'RW' => 'Rwanda', 'SC' => 'Seychelles', 'SD' => 'Sudan',
        'SL' => 'Sierra Leone', 'SN' => 'Senegal', 'SO' => 'Somalia', 'SS' => 'South Sudan',
        'ST' => 'São Tomé & Príncipe', 'SZ' => 'Eswatini', 'TD' => 'Chad', 'TG' => 'Togo',
        'TN' => 'Tunisia', 'TZ' => 'Tanzania', 'UG' => 'Uganda', 'ZA' => 'South Africa',
        'ZM' => 'Zambia', 'ZW' => 'Zimbabwe'
    ],
    'America' => [
        'AG' => 'Antigua & Barbuda', 'AI' => 'Anguilla', 'AR' => 'Argentina', 'AW' => 'Aruba',
        'BB' => 'Barbados', 'BO' => 'Bolivia', 'BR' => 'Brazil', 'BS' => 'Bahamas',
        'BZ' => 'Belize', 'CA' => 'Canada', 'CL' => 'Chile', 'CO' => 'Colombia',
        'CR' => 'Costa Rica', 'CU' => 'Cuba', 'DM' => 'Dominica', 'DO' => 'Dominican Republic',
        'EC' => 'Ecuador', 'GD' => 'Grenada', 'GT' => 'Guatemala', 'GY' => 'Guyana',
        'HN' => 'Honduras', 'HT' => 'Haiti', 'JM' => 'Jamaica', 'KN' => 'St. Kitts & Nevis',
        'KY' => 'Cayman Islands', 'LC' => 'St. Lucia', 'MX' => 'Mexico', 'NI' => 'Nicaragua',
        'PA' => 'Panama', 'PE' => 'Peru', 'PR' => 'Puerto Rico', 'PY' => 'Paraguay',
        'SR' => 'Suriname', 'SV' => 'El Salvador', 'TT' => 'Trinidad & Tobago',
        'US' => 'United States', 'UY' => 'Uruguay', 'VC' => 'St. Vincent & Grenadines',
        'VE' => 'Venezuela'
    ],
    'Antarctica' => [
        'AQ' => 'Antarctica'
    ],
    'Arctic' => [
        'SJ' => 'Svalbard & Jan Mayen'
    ],
    'Asia' => [
        'AE' => 'United Arab Emirates', 'AF' => 'Afghanistan', 'AM' => 'Armenia', 'AZ' => 'Azerbaijan',
        'BD' => 'Bangladesh', 'BH' => 'Bahrain', 'BN' => 'Brunei', 'BT' => 'Bhutan',
        'CN' => 'China', 'GE' => 'Georgia', 'HK' => 'Hong Kong', 'ID' => 'Indonesia',
        'IL' => 'Israel', 'IN' => 'India', 'IQ' => 'Iraq', 'IR' => 'Iran',
        'JO' => 'Jordan', 'JP' => 'Japan', 'KG' => 'Kyrgyzstan', 'KH' => 'Cambodia',
        'KP' => 'North Korea', 'KR' => 'South Korea', 'KW' => 'Kuwait', 'KZ' => 'Kazakhstan',
        'LA' => 'Laos', 'LB' => 'Lebanon', 'LK' => 'Sri Lanka', 'MM' => 'Myanmar',
        'MN' => 'Mongolia', 'MO' => 'Macao', 'MV' => 'Maldives', 'MY' => 'Malaysia',
        'NP' => 'Nepal', 'OM' => 'Oman', 'PH' => 'Philippines', 'PK' => 'Pakistan',
        'PS' => 'Palestine', 'QA' => 'Qatar', 'SA' => 'Saudi Arabia', 'SG' => 'Singapore',
        'SY' => 'Syria', 'TH' => 'Thailand', 'TJ' => 'Tajikistan', 'TL' => 'Timor-Leste',
        'TM' => 'Turkmenistan', 'TR' => 'Turkey', 'TW' => 'Taiwan', 'UZ' => 'Uzbekistan',
        'VN' => 'Vietnam', 'YE' => 'Yemen'
    ],
    'Atlantic' => [
        'BM' => 'Bermuda', 'CV' => 'Cape Verde', 'FK' => 'Falkland Islands',
        'FO' => 'Faroe Islands', 'GL' => 'Greenland', 'IS' => 'Iceland', 'SH' => 'St. Helena'
    ],
    'Australia' => [
        'AU' => 'Australia', 'FJ' => 'Fiji', 'NZ' => 'New Zealand', 'PG' => 'Papua New Guinea'
    ],
    'Europe' => [
        'AD' => 'Andorra', 'AL' => 'Albania', 'AT' => 'Austria', 'BA' => 'Bosnia & Herzegovina',
        'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BY' => 'Belarus', 'CH' => 'Switzerland',
        'CY' => 'Cyprus', 'CZ' => 'Czechia', 'DE' => 'Germany', 'DK' => 'Denmark',
        'EE' => 'Estonia', 'ES' => 'Spain', 'FI' => 'Finland', 'FR' => 'France',
        'GB' => 'United Kingdom', 'GR' => 'Greece', 'HR' => 'Croatia', 'HU' => 'Hungary',
        'IE' => 'Ireland', 'IT' => 'Italy', 'LI' => 'Liechtenstein', 'LT' => 'Lithuania',
        'LU' => 'Luxembourg', 'LV' => 'Latvia', 'MC' => 'Monaco', 'MD' => 'Moldova',
        'ME' => 'Montenegro', 'MK' => 'North Macedonia', 'MT' => 'Malta', 'NL' => 'Netherlands',
        'NO' => 'Norway', 'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania',
        'RS' => 'Serbia', 'RU' => 'Russia', 'SE' => 'Sweden', 'SI' => 'Slovenia',
        'SK' => 'Slovakia', 'SM' => 'San Marino', 'UA' => 'Ukraine', 'VA' => 'Vatican City'
    ]
];

// Procesar formularios POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $accion = $_POST['accion'] ?? '';

    // 1. Agregar Puerto Delicado
    if ($accion === 'agregar_puerto') {
        $puerto = (int) ($_POST['puerto'] ?? 0);
        $desc   = trim($_POST['descripcion'] ?? '');
        if ($puerto > 0 && $puerto <= 65535) {
            $stmt = $pdo->prepare("INSERT INTO configuracion_puertos_delicados (puerto, descripcion) VALUES (?, ?) ON DUPLICATE KEY UPDATE descripcion = VALUES(descripcion), activo = 1");
            $stmt->execute([$puerto, $desc]);
            $_SESSION['msg_texto'] = "Puerto {$puerto} agregado como delicado.";
            $_SESSION['msg_tipo'] = "success";
        }
    }

    // 2. Eliminar Puerto Delicado
    if ($accion === 'eliminar_puerto') {
        $id = (int) ($_POST['id'] ?? 0);
        $stmt = $pdo->prepare("DELETE FROM configuracion_puertos_delicados WHERE id = ?");
        $stmt->execute([$id]);
        $_SESSION['msg_texto'] = "Puerto eliminado de la vigilancia.";
        $_SESSION['msg_tipo'] = "info";
    }

    // 3. Guardar Selección GeoIP por Continente/Países
    if ($accion === 'guardar_geoip') {
        $seleccionados = $_POST['paises'] ?? []; // Array de códigos ISO marcados
        $setSeleccionados = array_flip($seleccionados);

        $pdo->beginTransaction();
        $pdo->exec("DELETE FROM configuracion_geoip_paises");
        $stmtIns = $pdo->prepare("INSERT INTO configuracion_geoip_paises (codigo_iso, nombre_pais, continente, seleccionado) VALUES (?, ?, ?, ?)");

        foreach ($regionesPaises as $continente => $paises) {
            foreach ($paises as $iso => $nombre) {
                $marcado = isset($setSeleccionados[$iso]) ? 1 : 0;
                $stmtIns->execute([$iso, $nombre, $continente, $marcado]);
            }
        }
        $pdo->commit();

        $_SESSION['msg_texto'] = "Configuración de países GeoIP guardada (" . count($seleccionados) . " países vigilados/bloqueados).";
        $_SESSION['msg_tipo'] = "success";
    }

    header('Location: configuracion_seguridad.php');
    exit;
}

$mensaje = $_SESSION['msg_texto'] ?? '';
$tipoAlerta = $_SESSION['msg_tipo'] ?? '';
unset($_SESSION['msg_texto'], $_SESSION['msg_tipo']);

// Cargar puertos delicados actuales
$puertosDelicados = $pdo->query("SELECT * FROM configuracion_puertos_delicados ORDER BY puerto ASC")->fetchAll(PDO::FETCH_ASSOC);

// Cargar países marcados actualmente en BD
$paisesMarcadosBD = $pdo->query("SELECT codigo_iso FROM configuracion_geoip_paises WHERE seleccionado = 1")->fetchAll(PDO::FETCH_COLUMN);
$mapaSeleccionados = array_flip($paisesMarcadosBD);

include 'views/header.php';
include 'views/menu.php';
?>

<!-- Librerías CSS para Select2 y Banderas de Países -->
<link href="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css" rel="stylesheet" />
<link href="https://cdn.jsdelivr.net/gh/lipis/flag-icons@7.0.0/css/flag-icons.min.css" rel="stylesheet" />
<style>
    .select2-container--default .select2-selection--multiple {
        background-color: #212529;
        border: 1px solid #495057;
        color: #fff;
        min-height: 42px;
    }
    .select2-container--default .select2-selection--multiple .select2-selection__choice {
        background-color: #343a40;
        border: 1px solid #6c757d;
        color: #f8f9fa;
        padding: 3px 8px;
    }
    .select2-container--default .select2-selection--multiple .select2-selection__choice__remove {
        color: #adb5bd;
        margin-right: 5px;
    }
    .select2-dropdown {
        background-color: #212529;
        color: #f8f9fa;
        border-color: #495057;
    }
    .select2-results__option--highlighted[aria-selected] {
        background-color: #0d6efd !important;
    }
    .region-counter {
        font-style: italic;
        font-size: 0.85rem;
        color: #6c757d;
        margin-top: 4px;
    }
    .btn-bulk-action {
        cursor: pointer;
        font-size: 1.2rem;
        color: #495057;
        transition: color 0.15s;
    }
    .btn-bulk-action:hover {
        color: #0d6efd;
    }
</style>

<div class="container mt-4 mb-5">
    <h2 class="mb-4"><i class="bi bi-sliders text-primary me-2"></i>Configuración de Puertos Delicados y GeoIP</h2>

    <?php if (!empty($mensaje)): ?>
        <div class="alert alert-<?= htmlspecialchars($tipoAlerta) ?> alert-dismissible fade show shadow-sm">
            <?= htmlspecialchars($mensaje) ?>
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    <?php endif; ?>

    <div class="row g-4">
        <!-- COLUMNA IZQUIERDA: GESTIÓN DE PUERTOS DELICADOS -->
        <div class="col-lg-4">
            <div class="card shadow-sm">
                <div class="card-header bg-dark text-white">
                    <h5 class="mb-0"><i class="bi bi-hdd-network me-2"></i>Puertos Delicados</h5>
                </div>
                <div class="card-body">
                    <p class="small text-muted">
                        Define los puertos donde corren servicios internos sensibles. Si una IP de los países seleccionados intenta acceder a ellos, se disparará una <strong>Alerta Especial</strong>.
                    </p>
                    <form method="POST" class="mb-3">
                        <input type="hidden" name="accion" value="agregar_puerto">
                        <div class="mb-2">
                            <label class="form-label small fw-bold">Número de Puerto</label>
                            <input type="number" name="puerto" class="form-control" placeholder="Ej: 4000, 21116, 3389" min="1" max="65535" required>
                        </div>
                        <div class="mb-3">
                            <label class="form-label small fw-bold">Servicio / Descripción</label>
                            <input type="text" name="descripcion" class="form-control" placeholder="Ej: NoMachine / RustDesk / ERP" required>
                        </div>
                        <button type="submit" class="btn btn-primary w-100">
                            <i class="bi bi-plus-circle me-1"></i> Agregar Puerto
                        </button>
                    </form>

                    <hr>
                    <h6 class="fw-bold mb-2">Puertos Bajo Vigilancia (<?= count($puertosDelicados) ?>)</h6>
                    <ul class="list-group list-group-flush">
                        <?php if (empty($puertosDelicados)): ?>
                            <li class="list-group-item text-muted small text-center">No hay puertos configurados aún.</li>
                        <?php else: ?>
                            <?php foreach ($puertosDelicados as $pd): ?>
                                <li class="list-group-item d-flex justify-content-between align-items-center px-0">
                                    <div>
                                        <span class="badge bg-danger me-2"><?= (int)$pd['puerto'] ?></span>
                                        <span class="small fw-semibold"><?= htmlspecialchars($pd['descripcion']) ?></span>
                                    </div>
                                    <form method="POST" class="m-0">
                                        <input type="hidden" name="accion" value="eliminar_puerto">
                                        <input type="hidden" name="id" value="<?= $pd['id'] ?>">
                                        <button type="submit" class="btn btn-sm btn-outline-danger" title="Quitar">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </form>
                                </li>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </ul>
                </div>
            </div>
        </div>

        <!-- COLUMNA DERECHA: SELECTOR GEOIP POR REGIÓN (ESTILO OPNSENSE) -->
        <div class="col-lg-8">
            <div class="card shadow-sm">
                <div class="card-header bg-dark text-white d-flex justify-content-between align-items-center">
                    <h5 class="mb-0"><i class="bi bi-globe-americas me-2"></i>Selección de Países (GeoLite2-Country)</h5>
                    <span class="badge bg-info text-dark">Países Vigilados / Bloqueados</span>
                </div>
                <div class="card-body">
                    <p class="small text-muted mb-3">
                        Selecciona los países que deben generar una <strong>Alerta Especial</strong> al intentar conectar con tus puertos delicados. (Por ejemplo, selecciona todos excepto Uruguay).
                    </p>

                    <form method="POST" id="formGeoIP">
                        <input type="hidden" name="accion" value="guardar_geoip">

                        <div class="table-responsive">
                            <table class="table align-middle">
                                <thead class="table-light">
                                    <tr>
                                        <th style="width: 140px;">Region</th>
                                        <th>Countries</th>
                                        <th style="width: 70px;" class="text-center">Acción</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($regionesPaises as $region => $paises): 
                                        $totalRegion = count($paises);
                                        $seleccionadosRegion = 0;
                                        foreach ($paises as $iso => $nombre) {
                                            if (isset($mapaSeleccionados[$iso])) $seleccionadosRegion++;
                                        }
                                        $regionId = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $region));
                                    ?>
                                    <tr>
                                        <td class="fw-bold align-top pt-3"><?= htmlspecialchars($region) ?></td>
                                        <td>
                                            <select name="paises[]" id="select_<?= $regionId ?>" class="form-select select2-geoip" multiple="multiple" data-region="<?= $regionId ?>" data-total="<?= $totalRegion ?>" style="width: 100%;">
                                                <?php foreach ($paises as $iso => $nombre): ?>
                                                    <option value="<?= $iso ?>" data-iso="<?= strtolower($iso) ?>" <?= isset($mapaSeleccionados[$iso]) ? 'selected' : '' ?>>
                                                        <?= htmlspecialchars($nombre) ?>
                                                    </option>
                                                <?php endforeach; ?>
                                            </select>
                                            <div class="region-counter" id="counter_<?= $regionId ?>">
                                                <?= $seleccionadosRegion ?> out of <?= $totalRegion ?> selected
                                            </div>
                                        </td>
                                        <td class="text-center align-top pt-3">
                                            <i class="bi bi-check-square btn-bulk-action me-1 seleccionar-todos" data-target="select_<?= $regionId ?>" title="Seleccionar todos en <?= $region ?>"></i>
                                            <i class="bi bi-square btn-bulk-action deseleccionar-todos" data-target="select_<?= $regionId ?>" title="Deseleccionar todos en <?= $region ?>"></i>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>

                        <div class="d-flex justify-content-end mt-3">
                            <button type="submit" class="btn btn-success px-4">
                                <i class="bi bi-save me-1"></i> Guardar Configuración GeoIP
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js"></script>
<script>
$(document).ready(function() {
    // Renderizar bandera junto al nombre del país
    function formatCountry(state) {
        if (!state.id) return state.text;
        const iso = $(state.element).data('iso');
        return $(`<span><span class="fi fi-${iso} me-1"></span> ${state.text}</span>`);
    }

    $('.select2-geoip').select2({
        templateResult: formatCountry,
        templateSelection: formatCountry,
        closeOnSelect: false,
        placeholder: "Selecciona países..."
    });

    // Actualizar contador "X out of Y selected" al cambiar selección
    $('.select2-geoip').on('change', function() {
        const region = $(this).data('region');
        const total = $(this).data('total');
        const count = $(this).val() ? $(this).val().length : 0;
        $(`#counter_${region}`).text(`${count} out of ${total} selected`);
    });

    // Botón Seleccionar Todos (☑)
    $('.seleccionar-todos').on('click', function() {
        const targetId = $(this).data('target');
        const $select = $(`#${targetId}`);
        const allValues = $select.find('option').map(function() { return $(this).val(); }).get();
        $select.val(allValues).trigger('change');
    });

    // Botón Deseleccionar Todos (☐)
    $('.deseleccionar-todos').on('click', function() {
        const targetId = $(this).data('target');
        const $select = $(`#${targetId}`);
        $select.val(null).trigger('change');
    });
});
</script>

<?php include 'views/footer.php'; ?>