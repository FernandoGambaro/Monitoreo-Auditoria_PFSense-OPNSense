<?php

declare(strict_types=1);

use phpseclib4\Net\SSH2;
use App\Encryption;

class PfSenseLogImporter
{
    private PDO $db;
    private int $firewallId;
    private int $importacionId = 0;
    private GeoIp $geoIp;

    public function __construct(PDO $db, int $firewallId)
    {
        $this->db = $db;
        $this->firewallId = $firewallId;
        $this->geoIp = new GeoIp();
    }

    /**
     * Comprueba si una dirección IP pertenece a un rango CIDR determinado
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return trim($ip) === trim($cidr);
        }
        list($subnet, $mask) = explode('/', $cidr);
        if ((string) ((int) $mask) !== (string) $mask || $mask < 0 || $mask > 32) {
            return false;
        }
        return (ip2long($ip) & ~((1 << (32 - (int) $mask)) - 1)) === ip2long($subnet);
    }

    /**
     * Procesa la IP de origen determinando si es interna (LAN/VLAN) o externa (GeoIP)
     */
    private function processIp(string $ip): ?int
    {
        // 1. Verificar si la IP ya existe en la tabla de IPs
        $stmt = $this->db->prepare("SELECT id FROM ips WHERE ip = ?");
        $stmt->execute([$ip]);
        $row = $stmt->fetch();

        if ($row) {
            return (int) $row['id'];
        }

        // 2. Comprobar si pertenece a alguna Red / VLAN configurada para este firewall
        $stmtRedes = $this->db->prepare("SELECT nombre, tipo, rango_cidr FROM firewall_redes WHERE firewall_id = ?");
        $stmtRedes->execute([$this->firewallId]);
        $redesConfiguradas = $stmtRedes->fetchAll(PDO::FETCH_ASSOC);

        $redDetectada = null;

        foreach ($redesConfiguradas as $red) {
            if ($this->ipInCidr($ip, $red['rango_cidr'])) {
                $redDetectada = $red['nombre'] . ' (' . $red['tipo'] . ')';
                break;
            }
        }

        // 3. Fallback: Si no hay redes configuradas, usar una subred básica basada en la IP del propio firewall
        if (!$redDetectada) {
            $stmtFw = $this->db->prepare("SELECT ip, nombre FROM firewalls WHERE id = ?");
            $stmtFw->execute([$this->firewallId]);
            $fwData = $stmtFw->fetch(PDO::FETCH_ASSOC);

            if ($fwData && !empty($fwData['ip'])) {
                // Generar subred /24 por defecto basada en la IP del firewall (ej. 192.168.1.X -> 192.168.1.0/24)
                $partesIp = explode('.', $fwData['ip']);
                if (count($partesIp) === 4) {
                    $subredBase = $partesIp[0] . '.' . $partesIp[1] . '.' . $partesIp[2] . '.0/24';
                    if ($this->ipInCidr($ip, $subredBase)) {
                        $redDetectada = 'Red Local LAN (' . $fwData['nombre'] . ')';
                    }
                }
            }
        }

        // 4. Registrar en la base de datos según sea IP Interna o Externa
        if ($redDetectada) {
            // Es una IP interna / VLAN configurada
            $pais = $redDetectada;
            $codigoPais = 'LAN';
            $ciudad = 'Red Interna';
            $isp = 'Infraestructura Local';
            $asn = 0;
            $reputacion = 'INTERNA';
            $abuseScore = 0;
        } else {
            // Es una IP externa, consultar GeoIP
            $geo = $this->geoIp->getInfo($ip);
            $pais = $geo['pais'] ?? 'DESCONOCIDO';
            $codigoPais = $geo['codigo_pais'] ?? null;
            $ciudad = $geo['ciudad'] ?? null;
            $isp = $geo['isp'] ?? null;
            $asn = $geo['asn'] ?? null;
            $reputacion = $geo['reputacion'] ?? 'DESCONOCIDA';
            $abuseScore = $geo['abuse_score'] ?? 0;
        }

        $insert = $this->db->prepare("
            INSERT INTO ips (ip, pais, codigo_pais, ciudad, isp, asn, reputacion, abuse_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $insert->execute([
            $ip,
            $pais,
            $codigoPais,
            $ciudad,
            $isp,
            $asn,
            $reputacion,
            $abuseScore
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function import(int $lines = 1000): array
    {
        // 1. Obtener los datos de conexión cifrados desde la BD
        $stmt = $this->db->prepare("SELECT * FROM firewalls WHERE id = ? AND activo = 1");
        $stmt->execute([$this->firewallId]);
        $fw = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$fw) {
            throw new Exception("El firewall ID {$this->firewallId} no existe o se encuentra inactivo.");
        }

        // 2. Descifrar la contraseña SSH
        $encryption = new Encryption();
        $passwordPlana = $encryption->decode($fw['password_ssh']);

        $this->crearImportacion($fw['nombre']);

        $ssh = new SSH2($fw['ip'], (int) $fw['puerto_ssh']);

        if (!$ssh->login($fw['usuario_ssh'], $passwordPlana)) {
            throw new Exception('No fue posible autenticar contra pfSense (' . $fw['ip'] . ').');
        }

        $rawLogs = $ssh->exec("tail -n {$lines} /var/log/filter.log");
        $rows = explode("\n", trim($rawLogs));

        $insertados = 0;
        $duplicados = 0;

        foreach ($rows as $row) {
            if (trim($row) === '') {
                continue;
            }

            $evento = $this->parseFilterLog($row);
            if (!$evento) {
                continue;
            }

            if ($this->insertEvent($evento)) {
                $insertados++;
            } else {
                $duplicados++;
            }
        }

        $this->actualizarImportacion(count($rows), $insertados);

        return [
            'procesados' => count($rows),
            'insertados' => $insertados,
            'duplicados' => $duplicados
        ];
    }

    private function crearImportacion(string $nombreFirewall): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO importaciones (nombre_archivo, hash_archivo, registros_archivo, registros_importados, fecha_importacion)
            VALUES (?, ?, 0, 0, NOW())
        ");

        $stmt->execute([
            'pfSense SSH - ' . $nombreFirewall,
            hash('sha256', uniqid('', true))
        ]);

        $this->importacionId = (int) $this->db->lastInsertId();
    }

    private function actualizarImportacion(int $registrosArchivo, int $registrosImportados): void
    {
        $stmt = $this->db->prepare("
            UPDATE importaciones
            SET registros_archivo = ?, registros_importados = ?
            WHERE id = ?
        ");
        $stmt->execute([$registrosArchivo, $registrosImportados, $this->importacionId]);
    }

    private function parseFilterLog(string $line): ?array
    {
        if (strpos($line, 'filterlog') === false) {
            return null;
        }

        $fecha = null;
        // Patrón combinado para capturar IPv4 o IPv6
        // 1. Extraer la fecha y hora del log (con su grupo de captura)
        $patronFecha = '/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})/';
        if (preg_match($patronFecha, $line, $matchesFecha)) {
            $dt = new DateTime($matchesFecha[1]);
            $fecha = $dt->format('Y-m-d H:i:s');
        } else {
            // Fecha por defecto o manejo si la línea no trae el formato esperado
            $fecha = date('Y-m-d H:i:s');
        }

        // 2. Extraer la dirección IP de origen (soporta IPv4 e IPv6)
        $patronIp = '/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';
        $ipOrigen = '';
        if (preg_match($patronIp, $line, $matchesIp)) {
            $ipOrigen = $matchesIp[0]; // $matchesIp[0] contiene la coincidencia completa de la IP
        }


        $data = substr($line, strpos($line, ']: ') + 3);
        $fields = explode(',', $data);
        $proto = strtoupper(trim($fields[16] ?? ''));

        if ($proto !== 'TCP' && $proto !== 'UDP') {
            return null;
        }

        return [
            'fecha_evento' => $fecha,
            'regla_id' => trim($fields[3] ?? ''),
            'interfaz' => trim($fields[4] ?? ''),
            'accion' => trim($fields[6] ?? ''),
            'direccion' => trim($fields[7] ?? ''),
            'ip_version' => trim($fields[8] ?? ''),
            'protocolo' => $proto,
            'ip_origen' => trim($fields[18] ?? ''),
            'ip_destino' => trim($fields[19] ?? ''),
            'puerto_origen' => (int) ($fields[20] ?? 0),
            'puerto_destino' => (int) ($fields[21] ?? 0),
            'flags' => trim($fields[23] ?? ''),
            'log_raw' => $line
        ];
    }

    private function insertEvent(array $evento): bool
    {
        $hash = hash('sha256', trim($evento['log_raw']));

        $sql = "
            INSERT IGNORE INTO firewall_eventos
            (
                firewall_id, importacion_id, ip_id, fecha_evento, interfaz, accion, 
                protocolo, ip_origen, ip_destino, puerto_origen, puerto_destino, descripcion, hash_evento
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ";

        $stmt = $this->db->prepare($sql);
        $ipId = $this->processIp($evento['ip_origen']);

        try {
            $stmt->execute([
                $this->firewallId,
                $this->importacionId,
                $ipId,
                $evento['fecha_evento'],
                $evento['interfaz'],
                strtoupper($evento['accion']),
                $evento['protocolo'],
                $evento['ip_origen'],
                $evento['ip_destino'],
                $evento['puerto_origen'],
                $evento['puerto_destino'],
                $evento['log_raw'],
                $hash
            ]);

            return ($stmt->rowCount() > 0);
        } catch (PDOException $e) {
            return false;
        }
    }
}


class OpnsenseLogImporter
{
    private PDO $db;
    private int $firewallId;
    private int $importacionId = 0;
    private GeoIp $geoIp;

    public function __construct(PDO $db, int $firewallId)
    {
        $this->db = $db;
        $this->firewallId = $firewallId;
        $this->geoIp = new GeoIp();
    }

    /**
     * Comprueba si una dirección IP pertenece a un rango CIDR determinado
     */
    private function ipInCidr(string $ip, string $cidr): bool
    {
        if (strpos($cidr, '/') === false) {
            return trim($ip) === trim($cidr);
        }
        list($subnet, $mask) = explode('/', $cidr);
        if ((string) ((int) $mask) !== (string) $mask || $mask < 0 || $mask > 32) {
            return false;
        }
        return (ip2long($ip) & ~((1 << (32 - (int) $mask)) - 1)) === ip2long($subnet);
    }

    /**
     * Procesa la IP de origen determinando si es interna (LAN/VLAN) o externa (GeoIP)
     */
    private function processIp(string $ip): ?int
    {
        // 1. Verificar si la IP ya existe en la tabla de IPs
        $stmt = $this->db->prepare("SELECT id FROM ips WHERE ip = ?");
        $stmt->execute([$ip]);
        $row = $stmt->fetch();

        if ($row) {
            return (int) $row['id'];
        }

        // 2. Comprobar si pertenece a alguna Red / VLAN configurada para este firewall
        $stmtRedes = $this->db->prepare("SELECT nombre, tipo, rango_cidr FROM firewall_redes WHERE firewall_id = ?");
        $stmtRedes->execute([$this->firewallId]);
        $redesConfiguradas = $stmtRedes->fetchAll(PDO::FETCH_ASSOC);

        $redDetectada = null;

        foreach ($redesConfiguradas as $red) {
            if ($this->ipInCidr($ip, $red['rango_cidr'])) {
                $redDetectada = $red['nombre'] . ' (' . $red['tipo'] . ')';
                break;
            }
        }

        // 3. Fallback: Si no hay redes configuradas, usar una subred básica basada en la IP del propio firewall
        if (!$redDetectada) {
            $stmtFw = $this->db->prepare("SELECT ip, nombre FROM firewalls WHERE id = ?");
            $stmtFw->execute([$this->firewallId]);
            $fwData = $stmtFw->fetch(PDO::FETCH_ASSOC);

            if ($fwData && !empty($fwData['ip'])) {
                // Generar subred /24 por defecto basada en la IP del firewall (ej. 192.168.1.X -> 192.168.1.0/24)
                $partesIp = explode('.', $fwData['ip']);
                if (count($partesIp) === 4) {
                    $subredBase = $partesIp[0] . '.' . $partesIp[1] . '.' . $partesIp[2] . '.0/24';
                    if ($this->ipInCidr($ip, $subredBase)) {
                        $redDetectada = 'Red Local LAN (' . $fwData['nombre'] . ')';
                    }
                }
            }
        }

        // 4. Registrar en la base de datos según sea IP Interna o Externa
        if ($redDetectada) {
            // Es una IP interna / VLAN configurada
            $pais = $redDetectada;
            $codigoPais = 'LAN';
            $ciudad = 'Red Interna';
            $isp = 'Infraestructura Local';
            $asn = 0;
            $reputacion = 'INTERNA';
            $abuseScore = 0;
        } else {
            // Es una IP externa, consultar GeoIP
            $geo = $this->geoIp->getInfo($ip);
            $pais = $geo['pais'] ?? 'DESCONOCIDO';
            $codigoPais = $geo['codigo_pais'] ?? null;
            $ciudad = $geo['ciudad'] ?? null;
            $isp = $geo['isp'] ?? null;
            $asn = $geo['asn'] ?? null;
            $reputacion = $geo['reputacion'] ?? 'DESCONOCIDA';
            $abuseScore = $geo['abuse_score'] ?? 0;
        }

        $insert = $this->db->prepare("
            INSERT INTO ips (ip, pais, codigo_pais, ciudad, isp, asn, reputacion, abuse_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ");

        $insert->execute([
            $ip,
            $pais,
            $codigoPais,
            $ciudad,
            $isp,
            $asn,
            $reputacion,
            $abuseScore
        ]);

        return (int) $this->db->lastInsertId();
    }

    public function import(int $lines = 1000): array
    {
        // 1. Obtener los datos de conexión cifrados desde la BD
        $stmt = $this->db->prepare("SELECT * FROM firewalls WHERE id = ? AND activo = 1");
        $stmt->execute([$this->firewallId]);
        $fw = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$fw) {
            throw new Exception("El firewall ID {$this->firewallId} no existe o se encuentra inactivo.");
        }

        // 2. Descifrar la contraseña SSH
        $encryption = new Encryption();
        $passwordPlana = $encryption->decode($fw['password_ssh']);

        $this->crearImportacion($fw['nombre']);

        $ssh = new SSH2($fw['ip'], (int) $fw['puerto_ssh']);

        if (!$ssh->login($fw['usuario_ssh'], $passwordPlana)) {
            throw new Exception('No fue posible autenticar contra OPNsense (' . $fw['ip'] . ').');
        }

        $nombreArchivoLog = 'filter_' . date('Ymd') . '.log';
        $rutaRemota = "/var/log/filter/{$nombreArchivoLog}";

        $rawLogs = $ssh->exec("tail -n {$lines} {$rutaRemota}");
        $rows = explode("\n", trim($rawLogs));

        $insertados = 0;
        $duplicados = 0;

        foreach ($rows as $row) {
            if (trim($row) === '') {
                continue;
            }

            $evento = $this->parseFilterLog($row);
            if (!$evento) {
                continue;
            }

            if ($this->insertEvent($evento)) {
                $insertados++;
            } else {
                $duplicados++;
            }
        }

        $this->actualizarImportacion(count($rows), $insertados);

        return [
            'procesados' => count($rows),
            'insertados' => $insertados,
            'duplicados' => $duplicados
        ];
    }

    private function crearImportacion(string $nombreFirewall): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO importaciones (nombre_archivo, hash_archivo, registros_archivo, registros_importados, fecha_importacion)
            VALUES (?, ?, 0, 0, NOW())
        ");

        $stmt->execute([
            'OPNsense SSH - ' . $nombreFirewall,
            hash('sha256', uniqid('', true))
        ]);

        $this->importacionId = (int) $this->db->lastInsertId();
    }

    private function actualizarImportacion(int $registrosArchivo, int $registrosImportados): void
    {
        $stmt = $this->db->prepare("
            UPDATE importaciones
            SET registros_archivo = ?, registros_importados = ?
            WHERE id = ?
        ");
        $stmt->execute([$registrosArchivo, $registrosImportados, $this->importacionId]);
    }

    private function parseFilterLog(string $line): ?array
    {
        if (strpos($line, 'filterlog') === false) {
            return null;
        }

        $fecha = null;
        // 1. Extraer la fecha y hora del log (con su grupo de captura)
        $patronFecha = '/(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})/';
        if (preg_match($patronFecha, $line, $matchesFecha)) {
            $dt = new DateTime($matchesFecha[1]);
            $fecha = $dt->format('Y-m-d H:i:s');
        } else {
            // Fecha por defecto o manejo si la línea no trae el formato esperado
            $fecha = date('Y-m-d H:i:s');
        }

        // 2. Extraer la dirección IP de origen (soporta IPv4 e IPv6)
        $patronIp = '/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/';
        $ipOrigen = '';
        if (preg_match($patronIp, $line, $matchesIp)) {
            $ipOrigen = $matchesIp[0]; // $matchesIp[0] contiene la coincidencia completa de la IP
        }



        $pos = strpos($line, ']');
        $data = ($pos !== false) ? trim(substr($line, $pos + 1), ' ,') : $line;
        $fields = explode(',', $data);

        if (count($fields) < 22) {
            return null;
        }

        $ipVersion = trim($fields[8] ?? '');
        if ($ipVersion !== '4' && $ipVersion !== '6') {
            return null;
        }

        if ($ipVersion === '6') {
            $proto = strtoupper(trim($fields[17] ?? ''));
            $ipOrigen = trim($fields[19] ?? '');
            $ipDestino = trim($fields[20] ?? '');
            $puertoOrigen = (int) ($fields[21] ?? 0);
            $puertoDestino = (int) ($fields[22] ?? 0);
        } else {
            $proto = strtoupper(trim($fields[16] ?? ''));
            $ipOrigen = trim($fields[18] ?? '');
            $ipDestino = trim($fields[19] ?? '');
            $puertoOrigen = (int) ($fields[20] ?? 0);
            $puertoDestino = (int) ($fields[21] ?? 0);
        }

        if ($proto !== 'TCP' && $proto !== 'UDP') {
            return null;
        }

        return [
            'fecha_evento' => $fecha,
            'regla_id' => trim($fields[3] ?? ''),
            'interfaz' => trim($fields[4] ?? ''),
            'accion' => trim($fields[6] ?? ''),
            'direccion' => trim($fields[7] ?? ''),
            'ip_version' => $ipVersion,
            'protocolo' => $proto,
            'ip_origen' => $ipOrigen,
            'ip_destino' => $ipDestino,
            'puerto_origen' => $puertoOrigen,
            'puerto_destino' => $puertoDestino,
            'flags' => '',
            'log_raw' => $line
        ];
    }

    private function insertEvent(array $evento): bool
    {
        $hash = hash('sha256', trim($evento['log_raw']));

        $sql = "
            INSERT IGNORE INTO firewall_eventos
            (
                firewall_id, importacion_id, ip_id, fecha_evento, interfaz, accion, 
                protocolo, ip_origen, ip_destino, puerto_origen, puerto_destino, descripcion, hash_evento
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ";

        $stmt = $this->db->prepare($sql);
        $ipId = $this->processIp($evento['ip_origen']);

        try {
            $stmt->execute([
                $this->firewallId,
                $this->importacionId,
                $ipId,
                $evento['fecha_evento'],
                $evento['interfaz'],
                strtoupper($evento['accion']),
                $evento['protocolo'],
                $evento['ip_origen'],
                $evento['ip_destino'],
                $evento['puerto_origen'],
                $evento['puerto_destino'],
                $evento['log_raw'],
                $hash
            ]);

            return ($stmt->rowCount() > 0);
        } catch (PDOException $e) {
            return false;
        }
    }
}
