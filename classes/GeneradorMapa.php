<?php

namespace Firewall;

class GeneradorMapa
{
    /**
     * Genera la imagen PNG del mapa mundial con los puntos de ataque superpuestos.
     * 
     * @param string $rutaBase Ruta al mapa base (ej. 'assets/images/mapamundi_base.png')
     * @param string $rutaSalida Ruta donde se guardará el mapa generado (ej. 'temp/graficos/mapa_mundial.png')
     * @param array $datosAtaques Array con formato [['pais' => 'Uruguay', 'lat' => -32.52, 'lon' => -55.76, 'total' => 1500], ...]
     */
    public static function generarMapaAmenazas(string $rutaBase, string $rutaSalida, array $datosAtaques): void
    {
        // Verificar si existe la imagen base
        if (!file_exists($rutaBase)) {
            return;
        }

        // Cargar imagen base (soporta PNG o JPG)
        $info = getimagesize($rutaBase);
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

        // Definir colores para las marcas (Rojo translúcido para alertas)
        $colorRojo = imagecolorallocatealpha($imagen, 220, 53, 69, 40); // Transparente
        $colorBorde = imagecolorallocate($imagen, 180, 20, 30);
        $colorTexto = imagecolorallocate($imagen, 255, 255, 255);

        foreach ($datosAtaques as $ataque) {
            $lat = $ataque['lat'] ?? 0;
            $lon = $ataque['lon'] ?? 0;
            $total = $ataque['total'] ?? 1;

            // Convertir Lat/Lon a coordenadas X/Y de la imagen (Proyección equirrectangular básica)
            // X = (Lon + 180) * (Ancho / 360)
            $x = (int) (($lon + 180) * ($ancho / 360));

            // Y = (90 - Lat) * (Alto / 180)
            $y = (int) (($lat + 90) * ($alto / 180));

            // Calcular radio del círculo basado en la cantidad de ataques (mínimo 5px, máximo 25px)
            $radio = min(max((int) (log($total + 1) * 3), 5), 25);

            // Dibujar círculo de impacto
            imagefilledellipse($imagen, $x, $y, $radio * 2, $radio * 2, $colorRojo);
            imageellipse($imagen, $x, $y, $radio * 2, $radio * 2, $colorBorde);
        }

        // Asegurar que el directorio de salida exista
        $dirSalida = dirname($rutaSalida);
        if (!is_dir($dirSalida)) {
            mkdir($dirSalida, 0755, true);
        }

        // Guardar imagen final
        imagepng($imagen, $rutaSalida);
        imagedestroy($imagen);
    }
}