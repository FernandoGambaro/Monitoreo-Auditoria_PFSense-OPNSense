<?php
// 1. Cargar el autoloader de Composer
require_once 'bootstrap.php';

// ==========================================
// CONFIGURACIÓN GLOBAL DE CONEXIÓN
// ==========================================

use phpseclib4\Net\SSH2;

// Inicializar la conexión usando las constantes globales
$ssh = new SSH2(PFSENSE_IP);

if (!$ssh->login(PFSENSE_USER, PFSENSE_PASS)) {
    exit('<h3 style="color:red;">Error: Falló la autenticación SSH. Revisa las credenciales en la configuración global.</h3>');
}
$raw_logs = $ssh->exec('tail -n 1500 /var/log/filter.log');
$lines = explode("\n", trim($raw_logs));
?>

<h2>Logs Interpretados de pfSense</h2>
<table border="1" cellpadding="5" style="border-collapse: collapse; width:100%;">
    <tr style="background:#333; color:#fff;">
        <th>Fecha/Hora Syslog</th>
        <th>Acción (Pass/Block)</th>
        <th>Interfaz</th>
        <th>Protocolo</th>
        <th>IP Origen</th>
        <th>IP Destino</th>
    </tr>
    <?php foreach ($lines as $line):
        if (trim($line) === '') continue;
        
        // Separar la marca de tiempo del mensaje principal
        $parts = preg_split('/\s+/', $line, 6);
        $timestamp = $parts[0] . ' ' . $parts[1] . ' ' . $parts[2];
        $message = $parts[5] ?? '';

        // El filterlog de pfSense pone los campos separados por comas después de "filterlog[PID]:"
        if (str_contains($message, 'filterlog')) {
            $data_part = substr($message, strpos($message, ']: ') + 3);
            $fields = explode(',', $data_part);
            
            // Campos comunes de pfSense filterlog:
            // [4] = Interface, [5] = action (pass/block), [6] = direction (in/out), [16] = proto, [18] = src IP, [19] = dst IP
            $interface = $fields[4] ?? 'N/A';
            $action    = $fields[5] ?? 'N/A';
            $proto     = $fields[16] ?? 'N/A';
            $src_ip    = $fields[18] ?? 'N/A';
            $dst_ip    = $fields[19] ?? 'N/A';
            
            $bg = ($action === 'block') ? '#ffcccc' : '#ccffcc';
            
            echo "<tr style='background-color: {$bg};'>
                    <td>{$timestamp}</td>
                    <td><strong>" . strtoupper($action) . "</strong></td>
                    <td>{$interface}</td>
                    <td>" . strtoupper($proto) . "</td>
                    <td>{$src_ip}</td>
                    <td>{$dst_ip}</td>
                  </tr>";
        } else {
            // Si es otro tipo de log del sistema (dhcpd, sshd, etc.)
            echo "<tr><td colspan='6'>{$line}</td></tr>";
        }
    endforeach; ?>
</table>