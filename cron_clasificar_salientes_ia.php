<?php
// Ejecutar vía CLI / Cron: php /ruta/proyecto/cron_clasificar_salientes_ia.php
if (php_sapi_name() !== 'cli') {
    die("Solo ejecutable desde CLI.");
}

require_once __DIR__ . '/bootstrap.php';
use Firewall\Database;
use PHPMailer\PHPMailer\PHPMailer;

$db = new Database();
$pdo = $db->getConnection();

// 1. Obtener IPs externas salientes nuevas (sin clasificar) + IPs para recaracterización (> 30 días)
$sqlCandidatas = "
    SELECT DISTINCT f.ip_destino AS ip, i.pais, i.abuse_score
    FROM firewall_eventos f
    LEFT JOIN ips_externas_confiables c ON f.ip_destino = c.ip
    LEFT JOIN ips i ON f.ip_destino = i.ip
    WHERE f.accion = 'PASS'
      AND (f.ip_origen LIKE '192.168.%' OR f.ip_origen LIKE '10.%' OR f.ip_origen LIKE '172.16.%')
      AND f.ip_destino NOT LIKE '192.168.%'
      AND f.ip_destino NOT LIKE '10.%'
      AND f.ip_destino NOT LIKE '172.16.%'
      AND f.fecha_evento >= NOW() - INTERVAL 24 HOUR
      AND (c.id IS NULL OR c.ultima_revision < NOW() - INTERVAL 30 DAY)
    LIMIT 30
";
$candidatas = $pdo->query($sqlCandidatas)->fetchAll(PDO::FETCH_ASSOC);

$apiKey = getenv('GEMINI_API_KEY');
$modelo = getenv('GEMINI_MODEL') ?: 'gemini-2.5-flash';

if (empty($apiKey)) {
    die("Error: GEMINI_API_KEY no está configurada en .env\n");
}

$urlGemini = "https://generativelanguage.googleapis.com/v1beta/models/" . urlencode($modelo) . ":generateContent?key=" . urlencode($apiKey);

foreach ($candidatas as $item) {
    $ip = $item['ip'];
    $ptr = @gethostbyaddr($ip);
    if ($ptr === $ip || $ptr === false)
        $ptr = 'Sin registro PTR';
    $pais = $item['pais'] ?? 'Desconocido';
    $abuse = (int) ($item['abuse_score'] ?? 0);

    if ($abuse > 25) {
        continue;
    }

    $prompt = "Analiza esta dirección IP externa a la que se conectó un equipo de nuestra red interna:
- IP: {$ip}
- Reverse DNS (PTR): {$ptr}
- País: {$pais}
- AbuseIPDB Score: {$abuse}/100

Responde ÚNICAMENTE con un objeto JSON válido con estas claves exactas:
{\"confiable\": true, \"confianza\": 90, \"categoria\": \"Cloud/OS/CDN/Desconocido\", \"propietario\": \"Nombre empresa o servicio\", \"justificacion\": \"Breve explicación técnica en español\"}";

    $payload = json_encode([
        'contents' => [
            ['parts' => [['text' => $prompt]]]
        ],
        'generationConfig' => [
            'responseMimeType' => 'application/json',
            'temperature' => 0.1
        ]
    ]);

    $ch = curl_init($urlGemini);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT => 25
    ]);
    $resp = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($resp && $httpCode === 200) {
        $jsonResp = json_decode($resp, true);
        $textoRespuesta = $jsonResp['candidates'][0]['content']['parts'][0]['text'] ?? '';
        $analisis = json_decode($textoRespuesta, true);

        if (is_array($analisis) && !empty($analisis['confiable']) && ($analisis['confianza'] ?? 0) >= 85) {
            $stmtUpsert = $pdo->prepare("
                INSERT INTO ips_externas_confiables 
                    (ip, descripcion, categoria, origen_validacion, confianza_ia, justificacion_ia, ultima_revision, notificada_reporte)
                VALUES (?, ?, ?, 'IA', ?, ?, NOW(), 0)
                ON DUPLICATE KEY UPDATE
                    descripcion = VALUES(descripcion),
                    categoria = VALUES(categoria),
                    origen_validacion = 'IA',
                    confianza_ia = VALUES(confianza_ia),
                    justificacion_ia = VALUES(justificacion_ia),
                    ultima_revision = NOW()
            ");
            $stmtUpsert->execute([
                $ip,
                $analisis['propietario'] ?? $ptr,
                $analisis['categoria'] ?? 'Gemini Validada',
                (int) $analisis['confianza'],
                $analisis['justificacion'] ?? ''
            ]);
        }
    }

    // Pausa breve (0.5s) para respetar los límites de peticiones por minuto (RPM) de la API gratuita/estándar
    usleep(500000);
}

// 2. Enviar Reporte Diario por Mail con las nuevas IPs agregadas (Manuales o por IA)
$nuevasConfiables = $pdo->query("
    SELECT * FROM ips_externas_confiables 
    WHERE notificada_reporte = 0 
    ORDER BY fecha_agregada ASC
")->fetchAll(PDO::FETCH_ASSOC);

if (!empty($nuevasConfiables) && getenv('ALERT_EMAIL_DESTINO')) {
    $cuerpo = "Reporte Diario de IPs Externas Validadas como Confiables (" . date('Y-m-d') . ")\n";
    $cuerpo .= "Total de IPs incorporadas hoy: " . count($nuevasConfiables) . "\n";
    $cuerpo .= str_repeat("=", 65) . "\n\n";

    foreach ($nuevasConfiables as $nc) {
        $cuerpo .= "• IP: {$nc['ip']} | Origen: {$nc['origen_validacion']} | Categoría: {$nc['categoria']}\n";
        $cuerpo .= "  Propietario/Desc: {$nc['descripcion']}\n";
        if (!empty($nc['justificacion_ia'])) {
            $cuerpo .= "  Análisis IA ({$nc['confianza_ia']}%): {$nc['justificacion_ia']}\n";
        }
        $cuerpo .= "\n";
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
        $mail->CharSet = 'UTF-8';

        $mail->setFrom(getenv('SMTP_USER'), 'Firewall Monitor - Whitelist IA');
        $mail->addAddress(getenv('ALERT_EMAIL_DESTINO'));
        $mail->Subject = "[Reporte Diario] " . count($nuevasConfiables) . " nuevas IPs externas validadas";
        $mail->Body = $cuerpo;
        $mail->send();

        // Marcar como notificadas para no repetirlas mañana
        $pdo->exec("UPDATE ips_externas_confiables SET notificada_reporte = 1 WHERE notificada_reporte = 0");
    } catch (Exception $e) {
        error_log("Error enviando reporte diario whitelist: " . $mail->ErrorInfo);
    }
}