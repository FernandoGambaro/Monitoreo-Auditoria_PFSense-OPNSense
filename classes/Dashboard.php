<?php

class Dashboard
{
    private PDO $db;

    public function __construct(PDO $db)
    {
        $this->db = $db;
    }

    public function totalEventos(): int
    {
        return (int)$this->db
            ->query("SELECT COUNT(*) FROM firewall_eventos")
            ->fetchColumn();
    }

    public function totalIps(): int
    {
        return (int)$this->db
            ->query("
                SELECT COUNT(DISTINCT ip_origen)
                FROM firewall_eventos
            ")
            ->fetchColumn();
    }

    public function totalPaises(): int
    {
        return (int)$this->db
            ->query("
                SELECT COUNT(DISTINCT pais)
                FROM ips
                WHERE pais IS NOT NULL
            ")
            ->fetchColumn();
    }

    public function fechaInicio()
    {
        return $this->db
            ->query("
                SELECT MIN(fecha_evento)
                FROM firewall_eventos
            ")
            ->fetchColumn();
    }

    public function fechaFin()
    {
        return $this->db
            ->query("
                SELECT MAX(fecha_evento)
                FROM firewall_eventos
            ")
            ->fetchColumn();
    }
}