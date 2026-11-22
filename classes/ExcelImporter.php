<?php

require_once __DIR__ .'/../bootstrap.php';

use PhpOffice\PhpSpreadsheet\IOFactory;

class ExcelImporter
{
    private PDO $db;

    private FirewallParser $parser;

    private GeoIp $geoIp;

    public function __construct(PDO $db)
    {
        $this->db = $db;

        $this->parser = new FirewallParser();

        $this->geoIp = new GeoIp();
    }

    public function import(array $file): array
    {
        if (!file_exists($file['tmp_name'])) {
            throw new Exception(
                'Archivo temporal no encontrado.'
            );
        }

        $hashArchivo =
            Utils::getFileHash(
                $file['tmp_name']
            );

        $stmt = $this->db->prepare(
            "SELECT id
             FROM importaciones
             WHERE hash_archivo=?"
        );

        $stmt->execute([$hashArchivo]);

        if ($stmt->fetch()) {

            return [
                'success' => false,
                'message' =>
                    'Archivo ya importado'
            ];
        }

        $spreadsheet =
            IOFactory::load(
                $file['tmp_name']
            );

        $sheet =
            $spreadsheet
                ->getActiveSheet();

        $rows =
            $sheet
                ->toArray();

        $this->db->beginTransaction();

        try {

            $importacion =
                $this->db->prepare(
                    "
                    INSERT INTO importaciones
                    (
                        nombre_archivo,
                        hash_archivo,
                        registros_archivo
                    )
                    VALUES
                    (?,?,?)
                    "
                );

            $importacion->execute([

                $file['name'],

                $hashArchivo,

                count($rows)
            ]);

            $importacionId =
                $this->db->lastInsertId();

            $insertados = 0;

            $fechaInicio = null;

            $fechaFin = null;

            foreach ($rows as $row) {

                $registro =
                    $this->parser
                        ->parse($row);

                if (!$registro) {
                    continue;
                }

                $fechaInicio ??=
                    $registro['fecha_evento'];

                $fechaFin =
                    $registro['fecha_evento'];

                $hashEvento =
                    Utils::generateEventHash(
                        $registro
                    );

                $insert =
                    $this->db->prepare(
                        "
                        INSERT IGNORE INTO firewall_eventos
                        (
                            importacion_id,
                            fecha_evento,
                            interfaz,
                            regla,
                            categoria_regla,
                            accion,
                            protocolo,
                            tcp_flags,
                            ip_origen,
                            puerto_origen,
                            ip_destino,
                            puerto_destino,
                            es_ipv6,
                            es_privada,
                            es_malicioso,
                            descripcion,
                            hash_evento
                        )
                        VALUES
                        (
                            ?,?,?,?,?,?,?,?,?,?,
                            ?,?,?,?,?,?,?
                        )
                        "
                    );

                $insert->execute([

                    $importacionId,

                    $registro['fecha_evento'],

                    $registro['interfaz'],

                    $registro['regla'],

                    $registro['categoria_regla'],

                    $registro['accion'],

                    $registro['protocolo'],

                    $registro['tcp_flags'],

                    $registro['ip_origen'],

                    $registro['puerto_origen'],

                    $registro['ip_destino'],

                    $registro['puerto_destino'],

                    $registro['es_ipv6'],

                    $registro['es_privada'],

                    $registro['es_malicioso'],

                    $registro['descripcion'],

                    $hashEvento
                ]);

                if ($insert->rowCount()) {

                    $insertados++;

                    $this->processIp(
                        $registro['ip_origen']
                    );
                }
            }

            $upd =
                $this->db->prepare(
                    "
                    UPDATE importaciones
                    SET
                        registros_importados=?,
                        fecha_inicio_logs=?,
                        fecha_fin_logs=?
                    WHERE id=?
                    "
                );

            $upd->execute([

                $insertados,

                $fechaInicio,

                $fechaFin,

                $importacionId
            ]);

            $this->db->commit();

            return [

                'success' => true,

                'importados' => $insertados
            ];
        }
        catch (Exception $e) {

            $this->db->rollBack();

            throw $e;
        }
    }

    private function processIp(
        string $ip
    ): void
    {
        $stmt =
            $this->db->prepare(
                "SELECT id
                 FROM ips
                 WHERE ip=?"
            );

        $stmt->execute([$ip]);

        if ($stmt->fetch()) {
            return;
        }

        $geo =
            $this->geoIp
                ->getInfo($ip);

        $insert =
            $this->db->prepare(
                "
                INSERT INTO ips
                (
                    ip,
                    pais,
                    codigo_pais,
                    ciudad,
                    isp,
                    asn,
                    reputacion,
                    abuse_score
                )
                VALUES
                (?,?,?,?,?,?,?,?)
                "
            );

        $insert->execute([

            $ip,

            $geo['pais'],

            $geo['codigo_pais'],

            $geo['ciudad'],

            $geo['isp'],

            $geo['asn'],

            $geo['reputacion'],

            $geo['abuse_score']
        ]);
    }
}