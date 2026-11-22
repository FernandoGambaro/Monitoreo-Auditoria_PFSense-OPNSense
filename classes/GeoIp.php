<?php

declare(strict_types=1);

use GeoIp2\Database\Reader;

class GeoIp
{
    private Reader $reader;

    public function __construct()
    {
        $this->reader = new Reader(
            __DIR__ . '/../geoip/GeoLite2-Country.mmdb'
        );
    }

    public function getInfo(string $ip): array
    {
        try {

            if (
                filter_var(
                    $ip,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_NO_PRIV_RANGE |
                    FILTER_FLAG_NO_RES_RANGE
                ) === false
            ) {
                return [];
            }

            $record =
                $this->reader->country($ip);

            return [

                'pais' =>
                    $record->country->name,

                'codigo_pais' =>
                    $record->country->isoCode,

                'ciudad' =>
                    null,

                'isp' =>
                    null,

                'asn' =>
                    null,

                'reputacion' =>
                    'DESCONOCIDA',

                'abuse_score' =>
                    0
            ];

        } catch (Exception $e) {

            return [

                'pais' => 'DESCONOCIDO',

                'codigo_pais' => null,

                'ciudad' => null,

                'isp' => null,

                'asn' => null,

                'reputacion' => 'DESCONOCIDA',

                'abuse_score' => 0
            ];
        }
    }
}