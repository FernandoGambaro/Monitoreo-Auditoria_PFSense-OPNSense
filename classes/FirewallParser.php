<?php

class FirewallParser
{
    public function parse(array $row): ?array
    {
        if (empty(array_filter($row))) {
            return null;
        }

        if (count($row) < 6) {
            return null;
        }

        $fecha      = trim((string)($row[0] ?? ''));
        $interfaz   = trim((string)($row[1] ?? ''));
        $regla      = trim((string)($row[2] ?? ''));
        $sourceRaw  = trim((string)($row[3] ?? ''));
        $destRaw    = trim((string)($row[4] ?? ''));
        $protocolo  = trim((string)($row[5] ?? ''));

        [$ipOrigen, $puertoOrigen] =
            $this->extractIpPort($sourceRaw);

        [$ipDestino, $puertoDestino] =
            $this->extractIpPort($destRaw);

        if (!$ipOrigen) {
            return null;
        }

        $esIpv6 =
            filter_var(
                $ipOrigen,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV6
            ) !== false;

        return [

            'fecha_evento' => $this->normalizeDate($fecha),

            'interfaz' => $interfaz,

            'regla' => $regla,

            'categoria_regla' =>
                $this->getCategoriaRegla($regla),

            'accion' => 'BLOCK',

            'protocolo' =>
                $this->getProtocolName($protocolo),

            'tcp_flags' =>
                $this->extractFlags($protocolo),

            'ip_origen' => $ipOrigen,

            'puerto_origen' => $puertoOrigen,

            'ip_destino' => $ipDestino,

            'puerto_destino' => $puertoDestino,

            'es_ipv6' => $esIpv6 ? 1 : 0,

            'es_privada' =>
                $this->isPrivateIp($ipOrigen) ? 1 : 0,

            'es_malicioso' =>
                $this->isMalicious(
                    $interfaz,
                    $ipOrigen,
                    $this->getCategoriaRegla($regla)
                ),

            'descripcion' =>
                json_encode(
                    $row,
                    JSON_UNESCAPED_UNICODE
                )
        ];
    }

    private function normalizeDate(?string $date): ?string
    {
        if (!$date) {
            return null;
        }

        $formats = [

            'm/d/Y H:i:s',
            'd/m/Y H:i:s',
            'Y-m-d H:i:s'
        ];

        foreach ($formats as $format) {

            $dt = DateTime::createFromFormat(
                $format,
                $date
            );

            if ($dt) {
                return $dt->format(
                    'Y-m-d H:i:s'
                );
            }
        }

        return $date;
    }

    private function extractIpPort(string $value): array
    {
        $value = trim($value);

        $value = trim($value, '[]');

        if (!$value) {
            return [null, null];
        }

        if (substr_count($value, ':') > 1) {

            if (
                preg_match(
                    '/^(.*):([0-9]+)$/',
                    $value,
                    $m
                )
            ) {
                return [
                    trim($m[1]),
                    (int)$m[2]
                ];
            }

            return [
                trim($value),
                null
            ];
        }

        $parts = explode(':', $value);

        return [

            trim($parts[0] ?? ''),

            isset($parts[1])
                ? (int)$parts[1]
                : null
        ];
    }

    private function getProtocolName(
        string $protocol
    ): string
    {
        $tmp = explode(':', $protocol);

        return strtoupper(
            trim($tmp[0] ?? $protocol)
        );
    }

    private function extractFlags(
        string $protocol
    ): ?string
    {
        if (
            strpos($protocol, ':')
            === false
        ) {
            return null;
        }

        $tmp = explode(':', $protocol);

        return trim($tmp[1] ?? '');
    }

    private function getCategoriaRegla(
        string $rule
    ): string
    {
        $rule = strtoupper($rule);

        if (strpos($rule,'AFRICA')!==false) return 'AFRICA';
        if (strpos($rule,'ASIA')!==false) return 'ASIA';
        if (strpos($rule,'EUROPE')!==false) return 'EUROPE';
        if (strpos($rule,'SAMERICA')!==false) return 'SAMERICA';
        if (strpos($rule,'TOP')!==false) return 'TOP';
        if (strpos($rule,'PRI1')!==false) return 'PRI1';

        if (
            strpos($rule,'DEFAULT DENY')
            !== false
        ) {
            return 'DEFAULT_DENY';
        }

        return 'OTHER';
    }

    private function isPrivateIp(
        string $ip
    ): bool
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE |
            FILTER_FLAG_NO_RES_RANGE
        ) === false;
    }

    private function isMalicious(
        string $interfaz,
        string $ip,
        string $categoria
    ): int
    {
        if ($this->isPrivateIp($ip))
            return 0;

        if (
            str_starts_with(
                $ip,
                '224.'
            )
        ) {
            return 0;
        }

        if (
            stripos(
                $ip,
                'fe80:'
            ) === 0
        ) {
            return 0;
        }

        if (
            $ip === '0.0.0.0' ||
            $ip === '255.255.255.255'
        ) {
            return 0;
        }

        if (
            strtoupper($interfaz)
            === 'WAN'
        ) {
            return 1;
        }

        if (
            in_array(
                $categoria,
                [
                    'AFRICA',
                    'ASIA',
                    'EUROPE',
                    'SAMERICA',
                    'TOP',
                    'PRI1'
                ]
            )
        ) {
            return 1;
        }

        return 0;
    }
}