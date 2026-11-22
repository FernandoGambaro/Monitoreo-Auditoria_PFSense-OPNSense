<?php

class Utils
{
    public static function getFileHash(string $file): string
    {
        return hash_file('sha256', $file);
    }

    public static function generateEventHash(array $registro): string
    {
        return hash(
            'sha256',
            implode('|', [

                $registro['fecha_evento'] ?? '',
                $registro['interfaz'] ?? '',
                $registro['regla'] ?? '',
                $registro['ip_origen'] ?? '',
                $registro['puerto_origen'] ?? '',
                $registro['ip_destino'] ?? '',
                $registro['puerto_destino'] ?? '',
                $registro['protocolo'] ?? ''
            ])
        );
    }
}