<?php

namespace Firewall;

use PDO;
use Throwable;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

class AlertEngine
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Evalúa las reglas de seguridad sobre los eventos recientes de un firewall.
     */
    public function procesarAlertas(int $firewallId): array
    {
        $alertasGeneradas = 0;

        // 1. Regla: Fuerza Bruta por IP Externa (más de 30 bloqueos en los últimos 15 minutos)
        $alertasGeneradas += $this->evaluarFuerzaBrutaIp($firewallId, 30, 15);

        // 2. Regla CRÍTICA: Conexión PERMITIDA externa (pass) tras múltiples bloqueos recientes en el mismo puerto
        $alertasGeneradas += $this->evaluarPassTrasBloqueo($firewallId, 30);

        // 3. Regla ESPECIAL: Acceso o intento desde país vigilado hacia un puerto delicado
        $alertasGeneradas += $this->evaluarPuertosDelicadosGeoIP($firewallId, 15);

        // 4. Regla de Egress Filtering: Conexiones salientes desde equipos internos hacia IPs externas no confiables
        $alertasGeneradas += $this->evaluarConexionesSalientesSospechosas($firewallId, 15);

        return ['alertas_creadas' => $alertasGeneradas];
    }


    /**
     * Evalúa conexiones salientes (PASS) desde equipos de la red interna hacia IPs públicas
     * que aún no forman parte de la lista ips_externas_confiables.
     */
    private function evaluarConexionesSalientesSospechosas(int $firewallId, int $ventanaMinutos = 15): int
    {
        $sql = "
            SELECT 
                f.ip_origen AS ip_interna,
                f.ip_destino AS ip_externa,
                GROUP_CONCAT(DISTINCT f.puerto_destino ORDER BY f.puerto_destino SEPARATOR ', ') AS puertos,
                COUNT(*) AS total_conexiones,
                fw.nombre AS nombre_fw,
                i.pais,
                i.reputacion,
                COALESCE(i.abuse_score, 0) AS abuse_score
            FROM firewall_eventos f
            JOIN firewalls fw ON f.firewall_id = fw.id
            LEFT JOIN ips_externas_confiables c ON f.ip_destino = c.ip
            LEFT JOIN ips i ON f.ip_destino = i.ip
            WHERE f.firewall_id = ?
              AND f.accion = 'PASS'
              AND f.fecha_evento >= NOW() - INTERVAL ? MINUTE
              -- Origen debe ser una subred interna/privada
              AND (f.ip_origen LIKE '192.168.%' OR f.ip_origen LIKE '10.%' OR f.ip_origen LIKE '172.16.%')
              -- Destino debe ser una IP pública (excluir privadas, multicast y broadcast)
              AND f.ip_destino NOT LIKE '192.168.%'
              AND f.ip_destino NOT LIKE '10.%'
              AND f.ip_destino NOT LIKE '172.16.%'
              AND f.ip_destino NOT LIKE '224.%'
              AND f.ip_destino NOT LIKE '239.%'
              AND f.ip_destino != '255.255.255.255'
              -- Excluir IPs ya validadas como confiables
              AND c.id IS NULL
            GROUP BY f.ip_origen, f.ip_destino
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([$firewallId, $ventanaMinutos]);
        $salientes = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $nuevasAlertas = 0;

        foreach ($salientes as $row) {
            $ipInterna = $row['ip_interna'];
            $ipExterna = $row['ip_externa'];
            $puertos = $row['puertos'];
            $conexiones = (int) $row['total_conexiones'];
            $abuseScore = (int) $row['abuse_score'];
            $reputacion = strtoupper(trim($row['reputacion'] ?? ''));
            $pais = $row['pais'] ?? 'Desconocido';

            // Determinar si amerita alerta (reputación dudosa/mala o tráfico saliente recurrente no validado)
            $esRiesgosa = ($abuseScore >= 15 || in_array($reputacion, ['MALA', 'MALICIOSA', 'SOSPECHOSA', 'BAJA'], true));
            $esRecurrenteNoValidada = ($conexiones >= 5);

            if (!$esRiesgosa && !$esRecurrenteNoValidada) {
                continue;
            }

            // Evitar duplicar la misma alerta para el par (ip_interna -> ip_externa) en las últimas 4 horas
            $stmtCheck = $this->db->prepare("
                SELECT COUNT(*) FROM firewall_alertas
                WHERE firewall_id = ?
                  AND tipo_alerta = 'CONEXION_SALIENTE_NO_CONFIABLE'
                  AND ip_origen = ?
                  AND mensaje LIKE ?
                  AND fecha_alerta >= NOW() - INTERVAL 4 HOUR
            ");
            $stmtCheck->execute([$firewallId, $ipExterna, "%{$ipInterna}%"]);

            if ($stmtCheck->fetchColumn() > 0) {
                continue;
            }

            $nivel = $esRiesgosa ? 'CRITICO' : 'ALTO';
            $motivo = $esRiesgosa
                ? "con reputación riesgosa (Score: {$abuseScore}/100, Rep: " . ($reputacion ?: 'N/A') . ")"
                : "no registrada en la lista de IPs confiables ({$conexiones} conexiones en {$ventanaMinutos} min)";

            $mensaje = "¡TRÁFICO SALIENTE SOSPECHOSO! El equipo interno {$ipInterna} estableció conexión PERMITIDA (PASS) hacia la IP externa {$ipExterna} ({$pais}) {$motivo} en los puertos [{$puertos}] a través de '{$row['nombre_fw']}'.";

            // Guardamos ip_externa en ip_origen de la alerta para que el enlace a VirusTotal y el modal de historial funcionen directamente
            $this->registrarAlerta(
                $firewallId,
                'CONEXION_SALIENTE_NO_CONFIABLE',
                $nivel,
                $ipExterna,
                $pais,
                0,
                $mensaje
            );

            if ($nivel === 'CRITICO') {
                $this->enviarNotificacionEmail("ALERTA CRÍTICA Saliente: {$ipInterna} -> {$ipExterna} ({$pais})", $mensaje);
            }

            $nuevasAlertas++;
        }

        return $nuevasAlertas;
    }

    /**
     * Evalúa intentos de conexión hacia puertos marcados como delicados
     * desde países seleccionados en la configuración GeoIP (MaxMind).
     */
    private function evaluarPuertosDelicadosGeoIP(int $firewallId, int $ventanaMinutos): int
    {
        // 1. Obtener puertos delicados activos
        $puertos = $this->db->query("SELECT puerto, descripcion FROM configuracion_puertos_delicados WHERE activo = 1")
            ->fetchAll(PDO::FETCH_KEY_PAIR); // [puerto => descripcion]
        if (empty($puertos)) {
            return 0;
        }

        // 2. Obtener países vigilados/bloqueados (ISO => Nombre)
        $paisesVigilados = $this->db->query("SELECT codigo_iso, nombre_pais FROM configuracion_geoip_paises WHERE seleccionado = 1")
            ->fetchAll(PDO::FETCH_KEY_PAIR);
        if (empty($paisesVigilados)) {
            return 0;
        }

        $placeholdersPuertos = implode(',', array_fill(0, count($puertos), '?'));
        $params = array_merge([$firewallId, $ventanaMinutos], array_keys($puertos));

        $sql = "
            SELECT f.ip_origen, f.puerto_destino, f.accion, COUNT(*) AS intentos, fw.nombre AS nombre_fw
            FROM firewall_eventos f
            JOIN firewalls fw ON f.firewall_id = fw.id
            WHERE f.firewall_id = ?
              AND f.fecha_evento >= NOW() - INTERVAL ? MINUTE
              AND f.puerto_destino IN ({$placeholdersPuertos})
              AND f.ip_origen NOT LIKE '192.168.%'
              AND f.ip_origen NOT LIKE '10.%'
              AND f.ip_origen NOT LIKE '172.16.%'
            GROUP BY f.ip_origen, f.puerto_destino, f.accion
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        $eventos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        // Inicializar lector de MaxMind GeoLite2-Country.mmdb si está disponible
        $mmdbPath = getenv('MAXMIND_DB_PATH') ?: __DIR__ . '/../../data/GeoLite2-Country.mmdb';
        $reader = (class_exists('\GeoIp2\Database\Reader') && file_exists($mmdbPath))
            ? new \GeoIp2\Database\Reader($mmdbPath)
            : null;

        $nuevasAlertas = 0;

        foreach ($eventos as $evt) {
            $ip = $evt['ip_origen'];
            $puerto = (int) $evt['puerto_destino'];
            $accion = strtoupper($evt['accion']);
            $intentos = (int) $evt['intentos'];
            $isoDetectado = null;
            $nombrePais = 'Desconocido';

            // Resolver país con MaxMind GeoLite2-Country.mmdb
            if ($reader !== null) {
                try {
                    $record = $reader->country($ip);
                    $isoDetectado = $record->country->isoCode;
                    $nombrePais = $record->country->name ?? $isoDetectado;
                } catch (Throwable $e) {
                    // IP no encontrada en MMDB
                }
            }

            // Verificar si el código ISO está en los países seleccionados
            if ($isoDetectado && isset($paisesVigilados[$isoDetectado])) {
                $stmtCheck = $this->db->prepare("
                    SELECT COUNT(*) FROM firewall_alertas 
                    WHERE firewall_id = ? AND tipo_alerta = 'PUERTO_DELICADO_GEOIP' 
                      AND ip_origen = ? AND puerto_destino = ?
                      AND fecha_alerta >= NOW() - INTERVAL 1 HOUR
                ");
                $stmtCheck->execute([$firewallId, $ip, $puerto]);

                if ($stmtCheck->fetchColumn() == 0) {
                    $servicio = $puertos[$puerto] ?: "Puerto {$puerto}";
                    $mensaje = "¡ALERTA ESPECIAL! La IP {$ip} ({$nombrePais} [{$isoDetectado}]) registró {$intentos} evento(s) ({$accion}) hacia el puerto delicado {$puerto} ({$servicio}) en '{$evt['nombre_fw']}'.";

                    $this->registrarAlerta($firewallId, 'PUERTO_DELICADO_GEOIP', 'CRITICO', $ip, $nombrePais, $puerto, $mensaje);
                    $this->enviarNotificacionEmail("ALERTA ESPECIAL Puerto Delicado {$puerto} - {$ip} ({$nombrePais})", $mensaje);
                    $nuevasAlertas++;
                }
            }
        }

        return $nuevasAlertas;
    }

    /**
     * Detecta si una IP externa tuvo bloqueos y luego logró un acceso PASS en los últimos N minutos.
     */
    private function evaluarPassTrasBloqueo(int $firewallId, int $ventanaMinutos): int
    {
        $sql = "
            SELECT f_pass.ip_origen, f_pass.puerto_destino AS puerto_exito, f_pass.fecha_evento, i.pais, fw.nombre AS nombre_fw,
                   GROUP_CONCAT(DISTINCT f_block.puerto_destino ORDER BY f_block.puerto_destino SEPARATOR ', ') AS puertos_bloqueados
            FROM firewall_eventos f_pass
            JOIN firewall_eventos f_block 
                ON f_pass.ip_origen = f_block.ip_origen 
               AND f_pass.firewall_id = f_block.firewall_id
            JOIN firewalls fw ON f_pass.firewall_id = fw.id
            LEFT JOIN ips i ON f_pass.ip_origen = i.ip
            WHERE f_pass.firewall_id = ?
              AND LOWER(f_pass.accion) = 'pass'
              AND LOWER(f_block.accion) = 'block'
              AND f_block.fecha_evento < f_pass.fecha_evento
              AND f_block.fecha_evento >= f_pass.fecha_evento - INTERVAL 30 MINUTE
              AND f_pass.fecha_evento >= NOW() - INTERVAL ? MINUTE
              AND f_pass.ip_origen NOT LIKE '192.168.%'
              AND f_pass.ip_origen NOT LIKE '10.%'
              AND f_pass.ip_origen NOT LIKE '172.16.%'
              AND (i.reputacion IS NULL OR i.reputacion != 'INTERNA')
            GROUP BY f_pass.ip_origen, f_pass.puerto_destino, f_pass.fecha_evento
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([$firewallId, $ventanaMinutos]);
        $eventosSospechosos = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $nuevasAlertas = 0;
        foreach ($eventosSospechosos as $evt) {
            $ip = $evt['ip_origen'];
            $puertoExito = (int) $evt['puerto_exito'];
            $puertosBloqueados = $evt['puertos_bloqueados'] ?? 'N/A';
            $pais = $evt['pais'] ?? 'Desconocido';

            $stmtCheck = $this->db->prepare("
                SELECT COUNT(*) FROM firewall_alertas 
                WHERE firewall_id = ? AND tipo_alerta = 'PASS_TRAS_BLOQUEO' AND ip_origen = ? AND puerto_destino = ?
                  AND fecha_alerta >= NOW() - INTERVAL 1 HOUR
            ");
            $stmtCheck->execute([$firewallId, $ip, $puertoExito]);

            if ($stmtCheck->fetchColumn() == 0) {
                $mensaje = "¡ALERTA CRÍTICA! La IP externa {$ip} ({$pais}) registró bloqueos previos en los puertos [{$puertosBloqueados}] y posteriormente estableció una conexión PERMITIDA (PASS) al puerto {$puertoExito} en el firewall '{$evt['nombre_fw']}'.";

                $this->registrarAlerta($firewallId, 'PASS_TRAS_BLOQUEO', 'CRITICO', $ip, $pais, $puertoExito, $mensaje);
                $this->enviarNotificacionEmail("CRÍTICO: Acceso Permitido Tras Bloqueo - ({$pais}) {$ip}", $mensaje);
                $nuevasAlertas++;
            }
        }

        return $nuevasAlertas;
    }

    /**
     * Detecta ráfagas de bloqueos desde una sola IP externa.
     */
    private function evaluarFuerzaBrutaIp(int $firewallId, int $umbral, int $ventanaMinutos): int
    {
        $sql = "
            SELECT f.ip_origen, i.pais, COUNT(*) as total_bloqueos, fw.nombre AS nombre_fw
            FROM firewall_eventos f
            JOIN firewalls fw ON f.firewall_id = fw.id
            LEFT JOIN ips i ON f.ip_origen = i.ip
            WHERE f.firewall_id = ?
              AND LOWER(f.accion) = 'block'
              AND f.fecha_evento >= NOW() - INTERVAL ? MINUTE
              AND f.ip_origen NOT LIKE '192.168.%'
              AND f.ip_origen NOT LIKE '10.%'
              AND f.ip_origen NOT LIKE '172.16.%'
              AND (i.reputacion IS NULL OR i.reputacion != 'INTERNA')
            GROUP BY f.ip_origen
            HAVING total_bloqueos >= ?
        ";

        $stmt = $this->db->prepare($sql);
        $stmt->execute([$firewallId, $ventanaMinutos, $umbral]);
        $fuerzaBruta = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $nuevasAlertas = 0;
        foreach ($fuerzaBruta as $row) {
            $ip = $row['ip_origen'];
            $pais = $row['pais'] ?? 'Desconocido';
            $total = (int) $row['total_bloqueos'];

            $stmtCheck = $this->db->prepare("
                SELECT COUNT(*) FROM firewall_alertas 
                WHERE firewall_id = ? AND tipo_alerta = 'FUERZA_BRUTA_IP' AND ip_origen = ? 
                  AND fecha_alerta >= NOW() - INTERVAL 30 MINUTE
            ");
            $stmtCheck->execute([$firewallId, $ip]);

            if ($stmtCheck->fetchColumn() == 0) {
                // Fixed minor duplicate method check formatting inline
            }

            if ($stmtCheck->fetchColumn() == 0) {
                $mensaje = "Ráfaga de ataques detectada: La IP externa {$ip} ({$pais}) acumula {$total} bloqueos en los últimos {$ventanaMinutos} min en '{$row['nombre_fw']}'.";

                $this->registrarAlerta($firewallId, 'FUERZA_BRUTA_IP', 'ALTO', $ip, $pais, null, $mensaje);
                $this->enviarNotificacionEmail("ALERTA: Fuerza Bruta desde IP {$ip}", $mensaje);
                $nuevasAlertas++;
            }
        }

        return $nuevasAlertas;
    }

    private function registrarAlerta(int $firewallId, string $tipo, string $nivel, ?string $ip, ?string $pais, ?int $puerto, string $mensaje): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO firewall_alertas (firewall_id, tipo_alerta, nivel_riesgo, ip_origen, pais, puerto_destino, mensaje, leida, fecha_alerta)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, NOW())
        ");
        $stmt->execute([$firewallId, $tipo, $nivel, $ip, $pais, $puerto, $mensaje]);
    }

    private function enviarNotificacionEmail(string $asunto, string $cuerpo): void
    {
        $emailDestino = getenv('ALERT_EMAIL_DESTINO');
        if (empty($emailDestino)) {
            return; // Si no hay destinatario configurado, no hace nada
        }

        $mail = new PHPMailer(true);
        try {
            $mail->isSMTP();
            $mail->Host = getenv('SMTP_HOST');
            $mail->SMTPAuth = true;
            $mail->Username = getenv('SMTP_USER');
            $mail->Password = getenv('SMTP_PASS');
            $mail->SMTPSecure = 'ssl';
            $mail->Port = (int) (getenv('SMTP_PORT') ?: 465);
            $mail->Timeout = 5;
            $mail->CharSet = 'UTF-8';

            $mail->setFrom(getenv('SMTP_USER'), 'Firewall Monitor');
            $mail->addAddress($emailDestino);

            $mail->isHTML(false);
            $mail->Subject = "[SEGURIDAD FIREWALL] " . $asunto;
            $mail->Body = $cuerpo;

            $mail->send();
        } catch (Exception $e) {
            error_log("Error al enviar correo de alerta por SMTP: {$mail->ErrorInfo}");
        }
    }
}
