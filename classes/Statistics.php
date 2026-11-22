<?php

class Statistics
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function ataquesPorMinuto(): float
    {
        $inicio = $this->db
            ->query("
                SELECT MIN(fecha_evento)
                FROM firewall_eventos
            ")
            ->fetchColumn();

        $fin = $this->db
            ->query("
                SELECT MAX(fecha_evento)
                FROM firewall_eventos
            ")
            ->fetchColumn();

        if(!$inicio || !$fin)
            return 0;

        $minutos =
            (
                strtotime($fin)
                -
                strtotime($inicio)
            ) / 60;

        if($minutos <= 0)
            return 0;

        $total = $this->db
            ->query("
                SELECT COUNT(*)
                FROM firewall_eventos
            ")
            ->fetchColumn();

        return round(
            $total / $minutos,
            2
        );
    }
}