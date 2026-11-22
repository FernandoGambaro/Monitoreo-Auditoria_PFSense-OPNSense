<!DOCTYPE html>
<html lang="es">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Firewall Analyzer</title>

        <!-- Bootstrap 5.3.2 CSS + Bootstrap Icons -->
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">

        <!-- DataTables Bootstrap 5 CSS -->
        <link href="https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css" rel="stylesheet">

        <style>
            body {
                background-color: #f4f6f9;
                overflow-x: hidden;
            }
            /* Estructura Sidebar Izquierdo */
            .app-wrapper {
                display: flex;
                min-height: 100vh;
                width: 100%;
            }
            .sidebar-nav {
                width: 250px;
                min-width: 250px;
                background-color: #1e2229;
                color: #fff;
                display: flex;
                flex-direction: column;
                transition: all 0.25s ease;
            }
            .sidebar-nav .brand-box {
                padding: 1.1rem 1.25rem;
                background-color: #15181e;
                border-bottom: 1px solid #2d323c;
                font-weight: 700;
                font-size: 1.15rem;
                letter-spacing: 0.3px;
            }
            .sidebar-nav .nav-link {
                color: #b8c2cc;
                padding: 0.65rem 1.25rem;
                font-size: 0.92rem;
                border-left: 3px solid transparent;
                display: flex;
                align-items: center;
                gap: 10px;
                transition: all 0.15s;
            }
            .sidebar-nav .nav-link:hover {
                color: #ffffff;
                background-color: #282d37;
            }
            .sidebar-nav .nav-link.active {
                color: #ffffff;
                background-color: #282d37;
                border-left-color: #0d6efd;
                font-weight: 600;
            }
            .sidebar-section-title {
                font-size: 0.72rem;
                text-transform: uppercase;
                letter-spacing: 0.8px;
                color: #6c757d;
                padding: 1rem 1.25rem 0.35rem;
                font-weight: 700;
            }
            .main-content-wrapper {
                flex: 1;
                min-width: 0;
                display: flex;
                flex-direction: column;
            }
            @media (max-width: 991.98px) {
                .sidebar-nav {
                    position: fixed;
                    top: 0;
                    bottom: 0;
                    left: -250px;
                    z-index: 1045;
                }
                .sidebar-nav.show {
                    left: 0;
                }
            }
        </style>
    </head>
    <body>
        <div class="app-wrapper">