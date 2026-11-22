<?php
$paginaActual = basename($_SERVER['PHP_SELF']);
?>

<!-- Menú Lateral Izquierdo (Sidebar) -->
<aside class="sidebar-nav shadow" id="sidebarMenu">
    <div class="brand-box d-flex justify-content-between align-items-center">
        <a href="dashboard.php" class="text-white text-decoration-none d-flex align-items-center gap-2">
            <i class="bi bi-shield-lock-fill text-primary fs-4"></i>
            <span>Firewall Analyzer</span>
        </a>
        <button class="btn btn-sm btn-outline-secondary d-lg-none text-white" id="btnCerrarSidebar">
            <i class="bi bi-x-lg"></i>
        </button>
    </div>

    <div class="sidebar-section-title">Monitoreo</div>
    <nav class="nav flex-column">
        <a class="nav-link <?= ($paginaActual === 'dashboard.php') ? 'active' : '' ?>" href="dashboard.php">
            <i class="bi bi-speedometer2"></i> Dashboard
        </a>
        <a class="nav-link <?= ($paginaActual === 'alertas.php') ? 'active' : '' ?>" href="alertas.php">
            <i class="bi bi-bell-fill text-warning"></i> Alertas de Seguridad
        </a>
        <a class="nav-link <?= ($paginaActual === 'logs.php') ? 'active' : '' ?>" href="logs.php">
            <i class="bi bi-journal-text"></i> Logs
        </a>
        <a class="nav-link <?= ($paginaActual === 'trafico_saliente.php') ? 'active' : '' ?>"
            href="trafico_saliente.php">
            <i class="bi bi-diagram-3 text-info"></i> Tráfico Saliente
        </a>
    </nav>

    <div class="sidebar-section-title">Análisis y Reportes</div>
    <nav class="nav flex-column">
        <a class="nav-link <?= ($paginaActual === 'reporte_puertos.php') ? 'active' : '' ?>" href="reporte_puertos.php">
            <i class="bi bi-hdd-network"></i> Puertos
        </a>
        <a class="nav-link <?= ($paginaActual === 'ips.php') ? 'active' : '' ?>" href="ips.php">
            <i class="bi bi-pc-display-horizontal"></i> IPs Únicas
        </a>
        <a class="nav-link <?= ($paginaActual === 'paises.php') ? 'active' : '' ?>" href="paises.php">
            <i class="bi bi-globe-americas"></i> Países
        </a>
        <a class="nav-link <?= ($paginaActual === 'reporte_word.php') ? 'active' : '' ?>" href="reporte_word.php">
            <i class="bi bi-file-earmark-word"></i> Reporte Word
        </a>
    </nav>

    <div class="sidebar-section-title">Administración</div>
    <nav class="nav flex-column mb-4">
        <a class="nav-link <?= ($paginaActual === 'configuracion_seguridad.php') ? 'active' : '' ?>"
            href="configuracion_seguridad.php">
            <i class="bi bi-sliders text-success"></i> Configurar Seguridad
        </a>
        <a class="nav-link <?= ($paginaActual === 'firewalls.php') ? 'active' : '' ?>" href="firewalls.php">
            <i class="bi bi-router"></i> Configurar Firewalls
        </a>
        <a class="nav-link <?= ($paginaActual === 'import_firewall.php') ? 'active' : '' ?>" href="import_firewall.php">
            <i class="bi bi-cloud-download"></i> Importar Firewall
        </a>
        <a class="nav-link <?= ($paginaActual === 'import.php') ? 'active' : '' ?>" href="import.php">
            <i class="bi bi-file-earmark-excel"></i> Importar Excel
        </a>
        <a class="nav-link <?= ($paginaActual === 'mantenimiento_bd.php') ? 'active' : '' ?>"
            href="mantenimiento_bd.php">
            <i class="bi bi-database-gear text-warning"></i> Mantenimiento BD
        </a>
    </nav>
</aside>

<!-- Contenedor Principal Derecho -->
<div class="main-content-wrapper">
    <!-- Barra superior solo visible en pantallas móviles/tablets para abrir el menú -->
    <div class="bg-dark text-white p-2 d-flex d-lg-none align-items-center justify-content-between">
        <button class="btn btn-sm btn-outline-light" id="btnAbrirSidebar">
            <i class="bi bi-list fs-5"></i> Menú
        </button>
        <span class="fw-bold">Firewall Analyzer</span>
        <span></span>
    </div>