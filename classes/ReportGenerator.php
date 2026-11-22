<?php

namespace Firewall;

use PhpOffice\PhpWord\PhpWord;
use PhpOffice\PhpWord\IOFactory;
use PhpOffice\PhpWord\SimpleType\Jc;
use PDO;
use Exception;

class ReportGenerator
{
    private PDO $db;

    public function __construct(PDO $database)
    {
        $this->db = $database;
    }

    /**
     * Genera el informe ejecutivo en Word para un rango de fechas o mes específico.
     *
     * @param string $archivoRuta Ruta completa de salida del archivo .docx
     * @param string|null $fechaInicio Formato Y-m-d
     * @param string|null $fechaFin Formato Y-m-d
     * @return string
     */
    public function generarMensual(string $archivoRuta, ?string $fechaInicio = null, ?string $fechaFin = null): string
    {
        // 1. Determinar rango de fechas si no fueron provistos
        $fechaInicio = $fechaInicio ?? date('Y-m-01');
        $fechaFin = $fechaFin ?? date('Y-m-t');

        $sqlInicio = $fechaInicio . ' 00:00:00';
        $sqlFin = $fechaFin . ' 23:59:59';

        // 2. Generar el mapa mundial de amenazas antes de compilar el Word
        $raizProyecto = dirname(__DIR__, 2);
        $rutaMapaSalida = $raizProyecto . '/tmp/mapa_mundial.png';
        $this->generarMapaAmenazasReal($sqlInicio, $sqlFin, $rutaMapaSalida);


        // 2. Generar el mapa mundial de amenazas antes de compilar el Word
        //$rutaMapaSalida = __DIR__ . '/../../tmp/mapa_mundial.png';
        $this->generarMapaAmenazasReal($sqlInicio, $sqlFin, $rutaMapaSalida);

        $phpWord = new PhpWord();

        // Configuración de Estilos Globales
        $phpWord->addTitleStyle(
            1,
            ['bold' => true, 'size' => 18, 'color' => '003366', 'name' => 'Arial'],
            ['spaceAfter' => 240, 'spaceBefore' => 240]
        );
        $phpWord->addTitleStyle(
            2,
            ['bold' => true, 'size' => 14, 'color' => '004080', 'name' => 'Arial'],
            ['spaceAfter' => 180, 'spaceBefore' => 180]
        );

        $section = $phpWord->addSection([
            'marginTop' => 1440, // 1 pulgada
            'marginBottom' => 1440,
            'marginLeft' => 1440,
            'marginRight' => 1440,
        ]);

        /* =========================================================================
         * PORTADA
         * ========================================================================= */
        $section->addTextBreak(3);
        $section->addText(
            'INFORME EJECUTIVO DE CIBERSEGURIDAD',
            ['bold' => true, 'size' => 24, 'color' => '003366', 'name' => 'Arial'],
            ['alignment' => Jc::CENTER]
        );

        $section->addTextBreak(1);
        $section->addText(
            'Actividad detectada por firewall OPNsense',
            ['size' => 14, 'italic' => true, 'color' => '555555', 'name' => 'Arial'],
            ['alignment' => Jc::CENTER]
        );

        $section->addTextBreak(2);
        $section->addText(
            'Período analizado: ' . date('d/m/Y', strtotime($fechaInicio)) . ' - ' . date('d/m/Y', strtotime($fechaFin)),
            ['size' => 11, 'bold' => true, 'color' => '333333', 'name' => 'Arial'],
            ['alignment' => Jc::CENTER]
        );

        $section->addPageBreak();

        /* =========================================================================
         * RESUMEN EJECUTIVO
         * ========================================================================= */
        $section->addTitle('Resumen Ejecutivo', 1);
        $section->addText(
            'Durante el período analizado se registraron e identificaron múltiples intentos de acceso no autorizado y escaneos de puertos que fueron bloqueados automáticamente por las reglas de filtrado del firewall perimetral corporativo.',
            ['size' => 11, 'name' => 'Arial'],
            ['spaceAfter' => 180]
        );

        /* =========================================================================
         * INDICADORES CLAVE (KPIs)
         * ========================================================================= */
        $section->addTitle('Indicadores Clave (KPIs)', 1);

        $kpis = $this->obtenerKPIsReal($sqlInicio, $sqlFin);

        $tableStyle = [
            'borderSize' => 6,
            'borderColor' => 'CCCCCC',
            'cellMargin' => 80,
            'alignment' => Jc::CENTER
        ];
        $phpWord->addTableStyle('KPI_Table', $tableStyle);
        $table = $section->addTable('KPI_Table');

        // Encabezado
        $table->addRow(400);
        $table->addCell(5000, ['bgColor' => '003366'])->addText('Indicador', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
        $table->addCell(3000, ['bgColor' => '003366'])->addText('Valor Registrado', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);

        foreach ($kpis as $kpi) {
            $table->addRow();
            $table->addCell(5000)->addText($kpi['nombre'], ['size' => 10, 'name' => 'Arial']);
            $table->addCell(3000)->addText($kpi['valor'], ['size' => 10, 'bold' => true, 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);
        }

        $section->addTextBreak(2);

        /* =========================================================================
         * IPs DE MAYOR RIESGO
         * ========================================================================= */
        $section->addTitle('IPs de Mayor Riesgo Detectadas', 1);

        $ipsRiesgo = $this->obtenerIpsMayorRiesgo($sqlInicio, $sqlFin);

        if (!empty($ipsRiesgo)) {
            $tableIps = $section->addTable('KPI_Table');
            $tableIps->addRow(400);
            $tableIps->addCell(3000, ['bgColor' => '003366'])->addText('Dirección IP', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
            $tableIps->addCell(2000, ['bgColor' => '003366'])->addText('País', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
            $tableIps->addCell(2000, ['bgColor' => '003366'])->addText('Reputación', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
            $tableIps->addCell(1500, ['bgColor' => '003366'])->addText('Eventos', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);

            foreach ($ipsRiesgo as $ipRow) {
                $tableIps->addRow();
                $tableIps->addCell(3000)->addText($ipRow['ip_origen'], ['size' => 9, 'name' => 'Arial']);
                $tableIps->addCell(2000)->addText($ipRow['pais'] ?? 'Desconocido', ['size' => 9, 'name' => 'Arial']);
                $tableIps->addCell(2000)->addText($ipRow['reputacion'] ?? 'DESCONOCIDA', ['size' => 9, 'bold' => true, 'name' => 'Arial']);
                $tableIps->addCell(1500)->addText(number_format((int) $ipRow['total_eventos']), ['size' => 9, 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);
            }
        } else {
            $section->addText('No se identificaron eventos de IP maliciosas en el rango seleccionado.', ['italic' => true, 'size' => 10, 'name' => 'Arial']);
        }

        /* =========================================================================
         * GRÁFICOS Y MAPAS
         * ========================================================================= */
        $section->addPageBreak();
        $section->addTitle('Gráficos Ejecutivos y Mapas', 1);

        // Incorporación dinámica de gráficos previos si existen
        if (file_exists('../../tmp/paises.png')) {
            $section->addTitle('Top Países de Origen de los Ataques', 2);
            $section->addImage('../../tmp/paises.png', ['width' => 450, 'alignment' => Jc::CENTER]);
            $section->addTextBreak(1);
        }

        // Incorporación del Mapa Mundial de Amenazas generado
        if (file_exists($rutaMapaSalida) && filesize($rutaMapaSalida) > 0) {
            $section->addTitle('Mapa Mundial de Amenazas', 2);
            $section->addImage($rutaMapaSalida, [
                'width' => 480,
                'alignment' => Jc::CENTER
            ]);
            $section->addTextBreak(1);
        }

        /* =========================================================================
         * ANÁLISIS DE PUERTOS DE DESTINO ATACADOS
         * ========================================================================= */
        $section->addTitle('Puertos de Destino Más Atacados (Top 10)', 1);
        $section->addText(
            'A continuación se detallan los servicios y puertos de red corporativos que registraron la mayor concentración de intentos de acceso bloqueados por el sistema perimetral:',
            ['size' => 10, 'name' => 'Arial'],
            ['spaceAfter' => 120]
        );

        $puertosAtacados = $this->obtenerPuertosMasAtacados($sqlInicio, $sqlFin);

        if (!empty($puertosAtacados)) {
            $tablePuertos = $section->addTable('KPI_Table');
            $tablePuertos->addRow(400);
            $tablePuertos->addCell(2000, ['bgColor' => '003366'])->addText('Puerto Destino', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
            $tablePuertos->addCell(4500, ['bgColor' => '003366'])->addText('Servicio / Protocolo Asociado', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial']);
            $tablePuertos->addCell(2000, ['bgColor' => '003366'])->addText('Total Bloqueos', ['bold' => true, 'color' => 'FFFFFF', 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);

            foreach ($puertosAtacados as $pRow) {
                $tablePuertos->addRow();
                $tablePuertos->addCell(2000)->addText((string) $pRow['puerto'], ['size' => 9, 'bold' => true, 'name' => 'Arial']);
                $tablePuertos->addCell(4500)->addText($pRow['servicio'], ['size' => 9, 'name' => 'Arial']);
                $tablePuertos->addCell(2000)->addText(number_format($pRow['total']), ['size' => 9, 'name' => 'Arial'], ['alignment' => Jc::RIGHT]);
            }
        } else {
            $section->addText('No se registraron bloqueos dirigiéndose a puertos específicos en el rango seleccionado.', ['italic' => true, 'size' => 10, 'name' => 'Arial']);
        }

        $section->addTextBreak(1);

        /* =========================================================================
         * RECOMENDACIONES Y CONCLUSIONES
         * ========================================================================= */
        $section->addPageBreak();
        $section->addTitle('Recomendaciones de Seguridad', 1);

        $section->addListItem('Mantener el cortafuegos OPNsense y sus paquetes (Unbound, Zenarmor) actualizados a la última versión estable.', 0, ['size' => 10, 'name' => 'Arial']);
        $section->addListItem('Implementar autenticación de múltiples factores (MFA) en todos los servicios de acceso remoto y VPN.', 0, ['size' => 10, 'name' => 'Arial']);
        $section->addListItem('Revisar y depurar periódicamente las reglas de NAT / Port Forwarding en la interfaz WAN para reducir la superficie de exposición.', 0, ['size' => 10, 'name' => 'Arial']);
        $section->addListItem('Capacitar al personal interno contra ataques de phishing e ingeniería social.', 0, ['size' => 10, 'name' => 'Arial']);
        $section->addListItem('Validar la integridad y frecuencia de los respaldos automatizados de la infraestructura.', 0, ['size' => 10, 'name' => 'Arial']);

        $section->addTitle('Conclusiones', 1);
        $section->addText(
            'El sistema de defensa perimetral ha mitigado eficazmente los intentos de escaneo y conexiones no autorizadas observados en el período. Se sugiere dar seguimiento a los bloques de direcciones IP identificadas como de alta peligrosidad.',
            ['size' => 10, 'name' => 'Arial']
        );

        if (file_exists($archivoRuta)) {
            @unlink($archivoRuta);
        }

        // Guardar documento
        $writer = IOFactory::createWriter($phpWord, 'Word2007');
        $writer->save($archivoRuta);

        return $archivoRuta;
    }

    /**
     * Genera el mapa mundial de amenazas superponiendo los puntos de ataque sobre la imagen base usando GD.
     */
    private function generarMapaAmenazasReal(string $sqlInicio, string $sqlFin, string $rutaSalida): void
    {
        // Usar una ruta basada en la raíz del proyecto de forma segura
        $raizProyecto = dirname(__DIR__, 1); // Sube dos niveles desde src/Firewall hasta la raíz
        $rutaBase = $raizProyecto . '/assets/World_map_blank_without_borders.png';

        if (!file_exists($rutaBase)) {
            // Opcional para depurar: puedes lanzar una excepción temporal si no encuentra la base
            throw new Exception("No se encontró la imagen base del mapa en: " . $rutaBase);
        }

        // Obtener totales de bloqueos agrupados por país desde la base de datos
        $stmt = $this->db->prepare("
            SELECT i.pais, COUNT(*) as total_bloqueos
            FROM firewall_eventos f
            JOIN ips i ON f.ip_origen = i.ip
            WHERE f.accion = 'BLOCK' 
              AND f.fecha_evento BETWEEN ? AND ?
              AND i.pais IS NOT NULL AND i.pais != ''
            GROUP BY i.pais
        ");
        $stmt->execute([$sqlInicio, $sqlFin]);
        $resultadosDb = $stmt->fetchAll(PDO::FETCH_KEY_PAIR);

        // Diccionario completo de coordenadas geográficas centrales por país
        $coordenadasPaises = [
            'Uruguay' => ['lat' => -32.52, 'lon' => -55.76],
            'Argentina' => ['lat' => -38.41, 'lon' => -63.61],
            'Brasil' => ['lat' => -14.23, 'lon' => -51.92],
            'Chile' => ['lat' => -35.67, 'lon' => -71.54],
            'Colombia' => ['lat' => 4.57, 'lon' => -74.29],
            'Perú' => ['lat' => -9.19, 'lon' => -75.01],
            'Venezuela' => ['lat' => 6.42, 'lon' => -66.58],
            'Ecuador' => ['lat' => -1.83, 'lon' => -78.18],
            'Estados Unidos' => ['lat' => 37.09, 'lon' => -95.71],
            'Canadá' => ['lat' => 56.13, 'lon' => -106.34],
            'México' => ['lat' => 23.63, 'lon' => -102.55],
            'Panamá' => ['lat' => 8.53, 'lon' => -80.78],
            'España' => ['lat' => 40.46, 'lon' => -3.74],
            'Francia' => ['lat' => 46.60, 'lon' => 2.21],
            'Alemania' => ['lat' => 51.16, 'lon' => 10.45],
            'Reino Unido' => ['lat' => 55.37, 'lon' => -3.43],
            'Italia' => ['lat' => 41.87, 'lon' => 12.56],
            'Países Bajos' => ['lat' => 52.13, 'lon' => 5.29],
            'Rusia' => ['lat' => 61.52, 'lon' => 105.31],
            'Ucrania' => ['lat' => 48.37, 'lon' => 31.16],
            'Polonia' => ['lat' => 51.91, 'lon' => 19.14],
            'China' => ['lat' => 35.86, 'lon' => 104.19],
            'Japón' => ['lat' => 36.20, 'lon' => 138.25],
            'India' => ['lat' => 20.59, 'lon' => 78.96],
            'Corea del Sur' => ['lat' => 35.90, 'lon' => 127.76],
            'Singapur' => ['lat' => 1.35, 'lon' => 103.81],
            'Vietnam' => ['lat' => 14.05, 'lon' => 108.27],
            'Sudáfrica' => ['lat' => -30.55, 'lon' => 22.93],
            'Egipto' => ['lat' => 26.82, 'lon' => 30.80],
            'Australia' => ['lat' => -25.27, 'lon' => 133.77],
        ];

        $datosAtaques = [];
        foreach ($resultadosDb as $paisNombre => $totalBloqueos) {
            if (isset($coordenadasPaises[$paisNombre])) {
                $datosAtaques[] = [
                    'pais' => $paisNombre,
                    'lat' => $coordenadasPaises[$paisNombre]['lat'],
                    'lon' => $coordenadasPaises[$paisNombre]['lon'],
                    'total' => (int) $totalBloqueos
                ];
            }
        }

        // Cargar imagen base del mapamundi (PNG)
        $info = @getimagesize($rutaBase);
        if ($info === false) {
            return;
        }

        $tipo = $info[2];
        if ($tipo === IMAGETYPE_PNG) {
            $imagen = imagecreatefrompng($rutaBase);
        } elseif ($tipo === IMAGETYPE_JPEG) {
            $imagen = imagecreatefromjpeg($rutaBase);
        } else {
            return;
        }

        $ancho = imagesx($imagen);
        $alto = imagesy($imagen);

        // Colores para los puntos (Rojo translúcido y borde oscuro)
        $colorRojo = imagecolorallocatealpha($imagen, 220, 53, 69, 40);
        $colorBorde = imagecolorallocate($imagen, 180, 20, 30);

        foreach ($datosAtaques as $ataque) {
            $lat = $ataque['lat'];
            $lon = $ataque['lon'];
            $total = $ataque['total'];

            // --- FÓRMULA CALIBRADA PARA EL MAPA BASE ---
            // Se ajusta la escala horizontal/vertical y se añaden offsets si el mapa tiene márgenes

            // Conversión ajustada para X (Longitud)
            $x = (int) (($lon + 180) * ($ancho / 360));

            // Corrección fina opcional si notas que un hemisferio se desplaza más que otro:
            // Por ejemplo, si los puntos de América necesitan correrse hacia la izquierda:
            // $x = $x + [desplazamiento_en_pixeles];

            // Conversión ajustada para Y (Latitud)
            // En las imágenes, Y=0 es arriba (+90) y Y=alto es abajo (-90)
            $y = (int) (($lat - 90) * -1 * ($alto / 180));

            // Radio proporcional basado en la cantidad de ataques
            $radio = min(max((int) (log($total + 1) * 3), 5), 25);

            imagefilledellipse($imagen, $x, $y, $radio * 2, $radio * 2, $colorRojo);
            imageellipse($imagen, $x, $y, $radio * 2, $radio * 2, $colorBorde);
        }

        $dirSalida = dirname($rutaSalida);
        if (!is_dir($dirSalida)) {
            mkdir($dirSalida, 0755, true);
        }

        imagepng($imagen, $rutaSalida);
        imagedestroy($imagen);
    }

    /**
     * Consulta las métricas reales directo de la base de datos MySQL/MariaDB
     */
    private function obtenerKPIsReal(string $sqlInicio, string $sqlFin): array
    {
        $stmt1 = $this->db->prepare("SELECT COUNT(*) FROM firewall_eventos WHERE accion = 'BLOCK' AND fecha_evento BETWEEN ? AND ?");
        $stmt1->execute([$sqlInicio, $sqlFin]);
        $bloqueados = (int) $stmt1->fetchColumn();

        $stmt2 = $this->db->prepare("SELECT COUNT(DISTINCT ip_origen) FROM firewall_eventos WHERE fecha_evento BETWEEN ? AND ?");
        $stmt2->execute([$sqlInicio, $sqlFin]);
        $ipsUnicas = (int) $stmt2->fetchColumn();

        $stmt3 = $this->db->prepare("
            SELECT COUNT(DISTINCT i.pais) 
            FROM firewall_eventos f
            JOIN ips i ON f.ip_origen = i.ip
            WHERE f.fecha_evento BETWEEN ? AND ?
        ");
        $stmt3->execute([$sqlInicio, $sqlFin]);
        $paises = (int) $stmt3->fetchColumn();

        $stmt4 = $this->db->prepare("
            SELECT COUNT(DISTINCT f.ip_origen) 
            FROM firewall_eventos f
            JOIN ips i ON f.ip_origen = i.ip
            WHERE f.fecha_evento BETWEEN ? AND ?
              AND UPPER(i.reputacion) IN ('MALA', 'MALICIOSA', 'SOSPECHOSA')
        ");
        $stmt4->execute([$sqlInicio, $sqlFin]);
        $ipsMaliciosas = (int) $stmt4->fetchColumn();

        $stmt5 = $this->db->prepare("SELECT COUNT(DISTINCT puerto_destino) FROM firewall_eventos WHERE accion = 'BLOCK' AND fecha_evento BETWEEN ? AND ?");
        $stmt5->execute([$sqlInicio, $sqlFin]);
        $puertosAtacados = (int) $stmt5->fetchColumn();

        return [
            ['nombre' => 'Conexiones bloqueadas', 'valor' => number_format($bloqueados)],
            ['nombre' => 'IPs únicas atacantes', 'valor' => number_format($ipsUnicas)],
            ['nombre' => 'Países de origen detectados', 'valor' => number_format($paises)],
            ['nombre' => 'IPs clasificadas como maliciosas/sospechosas', 'valor' => number_format($ipsMaliciosas)],
            ['nombre' => 'Puertos de destino atacados', 'valor' => number_format($puertosAtacados)],
        ];
    }

    /**
     * Obtiene el Top 10 de IPs con mayor volumen de bloqueos o mayor riesgo
     */
    private function obtenerIpsMayorRiesgo(string $sqlInicio, string $sqlFin): array
    {
        $stmt = $this->db->prepare("
            SELECT f.ip_origen, i.pais, i.reputacion, COUNT(*) as total_eventos
            FROM firewall_eventos f
            LEFT JOIN ips i ON f.ip_origen = i.ip
            WHERE f.accion = 'BLOCK'
              AND f.fecha_evento BETWEEN ? AND ?
            GROUP BY f.ip_origen, i.pais, i.reputacion
            ORDER BY total_eventos DESC
            LIMIT 10
        ");
        $stmt->execute([$sqlInicio, $sqlFin]);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    /**
     * Consulta el Top 10 de puertos de destino más atacados y resuelve nombres de servicios conocidos.
     */
    private function obtenerPuertosMasAtacados(string $sqlInicio, string $sqlFin): array
    {
        $stmt = $this->db->prepare("
            SELECT puerto_destino, COUNT(*) as total_bloqueos
            FROM firewall_eventos
            WHERE (accion = 'BLOCK' OR accion = 'block')
              AND fecha_evento BETWEEN ? AND ?
              AND puerto_destino > 0
            GROUP BY puerto_destino
            ORDER BY total_bloqueos DESC
            LIMIT 10
        ");
        $stmt->execute([$sqlInicio, $sqlFin]);
        $resultados = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $servicios = [
            21 => 'FTP (File Transfer Protocol)',
            22 => 'SSH (Secure Shell)',
            23 => 'Telnet (Unencrypted Text)',
            25 => 'SMTP (Simple Mail Transfer)',
            53 => 'DNS (Domain Name System)',
            80 => 'HTTP (Web Unencrypted)',
            110 => 'POP3 (Post Office Protocol)',
            143 => 'IMAP (Internet Message Access)',
            443 => 'HTTPS (Web Encrypted)',
            445 => 'SMB (Microsoft File Sharing)',
            1433 => 'MSSQL (Microsoft SQL Server)',
            3306 => 'MySQL Database Server',
            3389 => 'RDP (Remote Desktop Protocol)',
            5432 => 'PostgreSQL Database',
            8080 => 'HTTP-Proxy / Alternate Web'
        ];

        $puertosProcesados = [];
        foreach ($resultados as $row) {
            $p = (int) $row['puerto_destino'];
            $nombreServicio = $servicios[$p] ?? 'Servicio / Puerto no estándar';
            $puertosProcesados[] = [
                'puerto' => $p,
                'servicio' => $nombreServicio,
                'total' => (int) $row['total_bloqueos']
            ];
        }

        return $puertosProcesados;
    }

}