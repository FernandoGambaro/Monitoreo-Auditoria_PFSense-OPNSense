-- phpMyAdmin SQL Dump
-- version 5.2.3-1.fc43.remi
-- https://www.phpmyadmin.net/
--
-- Servidor: localhost
-- Tiempo de generación: 22-11-2026 a las 03:42:16
-- Versión del servidor: 10.11.18-MariaDB
-- Versión de PHP: 8.5.13

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `firewall_analyzer`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `configuracion_geoip_paises`
--

CREATE TABLE `configuracion_geoip_paises` (
  `codigo_iso` char(2) NOT NULL,
  `nombre_pais` varchar(100) NOT NULL,
  `continente` varchar(50) NOT NULL,
  `seleccionado` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `configuracion_puertos_delicados`
--

CREATE TABLE `configuracion_puertos_delicados` (
  `id` int(11) NOT NULL,
  `puerto` int(11) NOT NULL,
  `descripcion` varchar(100) DEFAULT NULL,
  `activo` tinyint(1) DEFAULT 1,
  `fecha_creacion` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `estadisticas_diarias`
--

CREATE TABLE `estadisticas_diarias` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `fecha` date NOT NULL,
  `total_eventos` int(11) NOT NULL,
  `ips_unicas` int(11) NOT NULL,
  `paises_unicos` int(11) NOT NULL,
  `eventos_maliciosos` int(11) NOT NULL,
  `promedio_minuto` decimal(10,2) DEFAULT NULL,
  `fecha_generacion` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewalls`
--

CREATE TABLE `firewalls` (
  `id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `tipo` enum('pfsense','opnsense') NOT NULL DEFAULT 'opnsense',
  `ip` varchar(45) NOT NULL,
  `puerto_ssh` int(11) DEFAULT 22,
  `usuario_ssh` varchar(50) NOT NULL,
  `password_ssh` text NOT NULL,
  `activo` tinyint(1) DEFAULT 1,
  `creado_en` timestamp NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewall_alertas`
--

CREATE TABLE `firewall_alertas` (
  `id` int(11) NOT NULL,
  `firewall_id` int(11) NOT NULL,
  `tipo_alerta` varchar(50) NOT NULL,
  `nivel_riesgo` enum('BAJO','MEDIO','ALTO','CRITICO') DEFAULT 'ALTO',
  `ip_origen` varchar(45) DEFAULT NULL,
  `pais` varchar(100) DEFAULT NULL,
  `puerto_destino` int(11) DEFAULT NULL,
  `mensaje` text NOT NULL,
  `leida` tinyint(1) DEFAULT 0,
  `fecha_alerta` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewall_alertas_config`
--

CREATE TABLE `firewall_alertas_config` (
  `id` int(11) NOT NULL,
  `nombre_regla` varchar(100) NOT NULL,
  `tipo_metrica` enum('bloqueos_por_ip','bloqueos_por_pais','conexion_sospechosa_tras_bloqueo') NOT NULL,
  `umbral_cantidad` int(11) DEFAULT 30,
  `ventana_tiempo_minutos` int(11) DEFAULT 10,
  `activo` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewall_eventos`
--

CREATE TABLE `firewall_eventos` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `firewall_id` int(11) DEFAULT 1,
  `importacion_id` bigint(20) UNSIGNED DEFAULT NULL,
  `ip_id` bigint(20) UNSIGNED DEFAULT NULL,
  `fecha_evento` datetime NOT NULL,
  `accion` varchar(20) NOT NULL,
  `interfaz` varchar(50) DEFAULT NULL,
  `protocolo` varchar(20) DEFAULT NULL,
  `ip_origen` varchar(45) DEFAULT NULL,
  `puerto_origen` int(11) DEFAULT NULL,
  `ip_destino` varchar(45) DEFAULT NULL,
  `puerto_destino` int(11) DEFAULT NULL,
  `descripcion` text DEFAULT NULL,
  `hash_evento` char(64) NOT NULL,
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp(),
  `regla` varchar(255) DEFAULT NULL,
  `tcp_flags` varchar(25) DEFAULT NULL,
  `categoria_regla` varchar(50) DEFAULT NULL,
  `es_ipv6` tinyint(1) DEFAULT 0,
  `es_privada` tinyint(1) DEFAULT 0,
  `es_malicioso` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewall_raw_logs`
--

CREATE TABLE `firewall_raw_logs` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `hash_log` char(64) NOT NULL,
  `log_raw` longtext NOT NULL,
  `fecha_importacion` datetime DEFAULT current_timestamp()
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `firewall_redes`
--

CREATE TABLE `firewall_redes` (
  `id` int(11) NOT NULL,
  `firewall_id` int(11) NOT NULL,
  `nombre` varchar(100) NOT NULL,
  `tipo` varchar(50) NOT NULL,
  `rango_cidr` varchar(50) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `importaciones`
--

CREATE TABLE `importaciones` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `nombre_archivo` varchar(255) NOT NULL,
  `hash_archivo` char(64) NOT NULL,
  `registros_archivo` int(11) NOT NULL DEFAULT 0,
  `registros_importados` int(11) NOT NULL DEFAULT 0,
  `fecha_inicio_logs` datetime DEFAULT NULL,
  `fecha_fin_logs` datetime DEFAULT NULL,
  `usuario` varchar(100) DEFAULT NULL,
  `fecha_importacion` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `importaciones_firewall`
--

CREATE TABLE `importaciones_firewall` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `fecha_inicio` datetime DEFAULT NULL,
  `fecha_fin` datetime DEFAULT NULL,
  `lineas_recibidas` int(11) DEFAULT 0,
  `eventos_importados` int(11) DEFAULT 0,
  `fecha_importacion` datetime DEFAULT current_timestamp()
) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `ips`
--

CREATE TABLE `ips` (
  `id` bigint(20) UNSIGNED NOT NULL,
  `ip` varchar(45) NOT NULL,
  `pais` varchar(100) DEFAULT NULL,
  `codigo_pais` varchar(5) DEFAULT NULL,
  `ciudad` varchar(100) DEFAULT NULL,
  `region` varchar(100) DEFAULT NULL,
  `isp` varchar(255) DEFAULT NULL,
  `asn` varchar(100) DEFAULT NULL,
  `reputacion` varchar(30) DEFAULT 'DESCONOCIDA',
  `abuse_score` smallint(6) DEFAULT 0,
  `total_reportes` int(11) DEFAULT 0,
  `primera_consulta` datetime DEFAULT NULL,
  `ultima_consulta` datetime DEFAULT NULL,
  `fecha_creacion` datetime NOT NULL DEFAULT current_timestamp()
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `ips_externas_confiables`
--

CREATE TABLE `ips_externas_confiables` (
  `id` int(11) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `descripcion` varchar(255) DEFAULT NULL,
  `categoria` varchar(100) DEFAULT NULL,
  `origen_validacion` enum('MANUAL','IA') DEFAULT 'MANUAL',
  `confianza_ia` tinyint(3) UNSIGNED DEFAULT NULL,
  `justificacion_ia` text DEFAULT NULL,
  `fecha_agregada` datetime DEFAULT current_timestamp(),
  `ultima_revision` datetime DEFAULT current_timestamp(),
  `notificada_reporte` tinyint(1) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `configuracion_geoip_paises`
--
ALTER TABLE `configuracion_geoip_paises`
  ADD PRIMARY KEY (`codigo_iso`);

--
-- Indices de la tabla `configuracion_puertos_delicados`
--
ALTER TABLE `configuracion_puertos_delicados`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `puerto` (`puerto`);

--
-- Indices de la tabla `estadisticas_diarias`
--
ALTER TABLE `estadisticas_diarias`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_fecha` (`fecha`);

--
-- Indices de la tabla `firewalls`
--
ALTER TABLE `firewalls`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `firewall_alertas`
--
ALTER TABLE `firewall_alertas`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_alerta_firewall` (`firewall_id`),
  ADD KEY `idx_alertas_leida_fecha` (`leida`,`fecha_alerta`);

--
-- Indices de la tabla `firewall_alertas_config`
--
ALTER TABLE `firewall_alertas_config`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `firewall_eventos`
--
ALTER TABLE `firewall_eventos`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_hash_evento` (`hash_evento`),
  ADD UNIQUE KEY `idx_hash_evento` (`hash_evento`),
  ADD KEY `fk_importacion` (`importacion_id`),
  ADD KEY `fk_ip` (`ip_id`),
  ADD KEY `idx_fecha_evento` (`fecha_evento`),
  ADD KEY `idx_ip_origen` (`ip_origen`),
  ADD KEY `idx_ip_destino` (`ip_destino`),
  ADD KEY `idx_puerto_destino` (`puerto_destino`),
  ADD KEY `idx_accion` (`accion`),
  ADD KEY `idx_protocolo` (`protocolo`),
  ADD KEY `idx_ip_fecha` (`ip_origen`,`fecha_evento`),
  ADD KEY `idx_fecha_puerto` (`fecha_evento`,`puerto_destino`),
  ADD KEY `idx_accion_fecha_origen_destino` (`accion`,`fecha_evento`,`ip_origen`,`ip_destino`);

--
-- Indices de la tabla `firewall_raw_logs`
--
ALTER TABLE `firewall_raw_logs`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `hash_log` (`hash_log`);

--
-- Indices de la tabla `firewall_redes`
--
ALTER TABLE `firewall_redes`
  ADD PRIMARY KEY (`id`),
  ADD KEY `fk_firewall_red` (`firewall_id`);

--
-- Indices de la tabla `importaciones`
--
ALTER TABLE `importaciones`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_hash_archivo` (`hash_archivo`),
  ADD KEY `idx_fecha_importacion` (`fecha_importacion`);

--
-- Indices de la tabla `importaciones_firewall`
--
ALTER TABLE `importaciones_firewall`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `ips`
--
ALTER TABLE `ips`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `uk_ip` (`ip`),
  ADD KEY `idx_pais` (`pais`),
  ADD KEY `idx_reputacion` (`reputacion`),
  ADD KEY `idx_abuse_score` (`abuse_score`);

--
-- Indices de la tabla `ips_externas_confiables`
--
ALTER TABLE `ips_externas_confiables`
  ADD PRIMARY KEY (`id`),
  ADD UNIQUE KEY `ip` (`ip`),
  ADD KEY `idx_notificada` (`notificada_reporte`),
  ADD KEY `idx_revision` (`ultima_revision`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `configuracion_puertos_delicados`
--
ALTER TABLE `configuracion_puertos_delicados`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `estadisticas_diarias`
--
ALTER TABLE `estadisticas_diarias`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewalls`
--
ALTER TABLE `firewalls`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewall_alertas`
--
ALTER TABLE `firewall_alertas`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewall_alertas_config`
--
ALTER TABLE `firewall_alertas_config`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewall_eventos`
--
ALTER TABLE `firewall_eventos`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewall_raw_logs`
--
ALTER TABLE `firewall_raw_logs`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `firewall_redes`
--
ALTER TABLE `firewall_redes`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `importaciones`
--
ALTER TABLE `importaciones`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `importaciones_firewall`
--
ALTER TABLE `importaciones_firewall`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `ips`
--
ALTER TABLE `ips`
  MODIFY `id` bigint(20) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `ips_externas_confiables`
--
ALTER TABLE `ips_externas_confiables`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `firewall_alertas`
--
ALTER TABLE `firewall_alertas`
  ADD CONSTRAINT `fk_alerta_firewall` FOREIGN KEY (`firewall_id`) REFERENCES `firewalls` (`id`) ON DELETE CASCADE;

--
-- Filtros para la tabla `firewall_redes`
--
ALTER TABLE `firewall_redes`
  ADD CONSTRAINT `fk_firewall_red` FOREIGN KEY (`firewall_id`) REFERENCES `firewalls` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
