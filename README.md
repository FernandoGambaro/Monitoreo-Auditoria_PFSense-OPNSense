# Visualizador y Analizador de Logs de Firewall (pfSense / OPNsense)

Plataforma web en PHP y MariaDB/MySQL diseñada para **visualizar gráficamente los registros del firewall distinguiendo tráfico entrante y saliente**, **inspeccionar direcciones IP y puertos bloqueados**, y **seleccionar puertos de especial interés** para vigilar servicios internos o expuestos de la red.

Incluye además soporte multi-motor para análisis asistido con IA (modelo local en red propia vía Ollama y/o Google Gemini), importación programada mediante `cron`, mantenimiento de base de datos por lotes, alertas de seguridad y consultas de reputación de IP (VirusTotal / AbuseIPDB).

---

## Tabla de Contenidos

1. [Características Principales](#características-principales)
2. [Requisitos del Sistema](#requisitos-del-sistema)
3. [Instalación y Despliegue](#instalación-y-despliegue)
   - [1. Clonado y Configuración de Base de Datos](#1-clonado-y-configuración-de-base-de-datos)
   - [2. Variables de Entorno (.env)](#2-variables-de-entorno-env)
   - [3. Despliegue en Linux con Apache2](#3-despliegue-en-linux-con-apache2)
   - [4. Despliegue en Linux con Nginx + PHP-FPM](#4-despliegue-en-linux-con-nginx--php-fpm)
   - [5. Despliegue en Windows con WAMP](#5-despliegue-en-windows-con-wamp)
4. [Configuración de los Firewalls](#configuración-de-los-firewalls)
   - [Configuración en pfSense](#configuración-en-pfsense)
   - [Configuración en OPNsense](#configuración-en-opnsense)
5. [Registro de Firewalls en el Sistema](#registro-de-firewalls-en-el-sistema)
6. [Tareas Programadas (Cron), Permisos de `tmp` y SELinux](#tareas-programadas-cron-permisos-de-tmp-y-selinux)
   - [Configuración de Cron](#configuración-de-cron)
   - [Permisos de la Carpeta `tmp` y Logs](#permisos-de-la-carpeta-tmp-y-logs)
   - [Configuración de SELinux](#configuración-de-selinux)
7. [Mantenimiento de Base de Datos](#mantenimiento-de-base-de-datos)
8. [Licencia](#licencia)

---

## Características Principales

* **Visualización Gráfica de Logs:** Gráficos interactivos y vistas tabulares paginadas (*server-side*) que diferencian claramente el tráfico **entrante** y **saliente**, facilitando la lectura rápida del comportamiento de la red.
* **Inspección de Bloqueos (IPs y Puertos):** Revisión detallada de conexiones bloqueadas (`BLOCK`) para auditar direcciones IP de origen/destino, frecuencia de intentos, países y puertos afectados, con enlaces directos a VirusTotal y AbuseIPDB.
* **Puertos de Especial Interés:** Selección y seguimiento focalizado de puertos críticos o relevantes (asociados a servicios internos, administración remota, bases de datos, correo, web, etc.) para detectar intentos de acceso o anomalías hacia servicios de la red.
* **Soporte Multi-Firewall:** Gestión centralizada de múltiples instancias de **pfSense** y **OPNsense** desde un único panel.
* **Evaluación Híbrida con IA (Local + Cloud):** Integración nativa con **Ollama** (modelos locales en red propia como `deepseek-coder-v2`, `llama3`, `qwen2.5`) y **Google Gemini** (`gemini-2.5-flash`), con soporte de *fallback* automático y gestión de listas blancas (*Whitelist*).
* **Mantenimiento de Base de Datos:** Herramienta integrada en *Administración → Mantenimiento BD* para depuración segura de registros históricos por lotes (`LIMIT 25000` vía AJAX) y actualización de estadísticas de índices.

---

## Requisitos del Sistema

* **PHP:** 8.1 o superior.
* **Extensiones PHP requeridas:** `pdo`, `pdo_mysql`, `curl`, `json`, `mbstring`, `intl`, `openssl`.
* **Base de Datos:** MariaDB 10.6+ o MySQL 8.0+ (con soporte `utf8mb4_unicode_ci`).
* **Servidor Web:** Apache 2.4+, Nginx 1.18+ o WAMP Server (Windows).
* **Firewalls Soportados:** pfSense y/o OPNsense con envío de logs por Syslog o acceso API/SSH configurado.
* **Opcional (IA):** Servidor Ollama accesible en la red local (`puerto 11434`) y/o API Key de Google Gemini.

---

## Instalación y Despliegue

### 1. Clonado y Configuración de Base de Datos

Clona el repositorio en el directorio raíz de tu servidor web:

```bash
git clone https://github.com/FernandoGambaro/Monitoreo-Auditoria_PFSense-OPNSense.git
cd Monitoreo-Auditoria_PFSense-OPNSense
```

Crea la base de datos y el usuario dedicado en MariaDB/MySQL:

```sql
CREATE DATABASE firewall_logs CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'fw_monitor'@'localhost' IDENTIFIED BY 'TuPasswordSegura';
GRANT ALL PRIVILEGES ON firewall_logs.* TO 'fw_monitor'@'localhost';
FLUSH PRIVILEGES;
```

Importa el esquema inicial de tablas (si dispones del archivo `.sql` en `/database` o `/sql`):

```bash
mysql -u fw_monitor -p firewall_logs < database/schema.sql
```

### 2. Variables de Entorno (`.env`)

Crea un archivo `.env` en la raíz del proyecto con la siguiente configuración:

```ini
# Base de Datos
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=firewall_logs
DB_USER=fw_monitor
DB_PASS=TuPasswordSegura
DB_CHARSET=utf8mb4

# Configuración de Inteligencia Artificial (Opcional)
# Proveedor por defecto: 'local' (Ollama en red propia) o 'gemini' (Google Cloud)
IA_PROVEEDOR_DEFAULT=local
# Fallback automático al proveedor secundario si el principal falla o agota tiempo (1 = activo, 0 = inactivo)
IA_FALLBACK_AUTOMATICO=1

# Proveedor Local (Ollama)
LOCAL_LLM_URL=http://192.168.x.x:11434
LOCAL_LLM_MODEL=deepseek-coder-v2:16b
LOCAL_LLM_TIMEOUT=45

# Proveedor Cloud (Google Gemini)
GEMINI_API_KEY=TuClaveDeApiAqui
GEMINI_MODEL=gemini-2.5-flash//o el modelo que elijas
```

> **Nota de Seguridad:** Asegúrate de que el archivo `.env` esté incluido en `.gitignore` y nunca se suba con credenciales reales al repositorio público.

---

### 3. Despliegue en Linux con Apache2

1. **Instalar paquetes necesarios (Debian/Ubuntu):**
   ```bash
   sudo apt update
   sudo apt install -y apache2 php php-cli php-fpm php-mysql php-curl php-mbstring php-xml php-intl mariadb-server
   ```

2. **Mover el proyecto y asignar permisos:**
   ```bash
   sudo mv firewall-monitor /var/www/html/firewall-monitor
   sudo chown -R www-data:www-data /var/www/html/firewall-monitor
   sudo chmod -R 755 /var/www/html/firewall-monitor
   sudo chmod 640 /var/www/html/firewall-monitor/.env
   ```

3. **Configurar VirtualHost (`/etc/apache2/sites-available/firewall-monitor.conf`):**
   ```apache
   <VirtualHost *:80>
       ServerName firewall-monitor.local
       DocumentRoot /var/www/html/firewall-monitor

       <Directory /var/www/html/firewall-monitor>
           Options -Indexes +FollowSymLinks
           AllowOverride All
           Require all granted
       </Directory>

       # Proteger archivo .env contra acceso web directo
       <Files ".env">
           Require all denied
       </Files>

       # Tiempo de espera ampliado para consultas IA y mantenimiento BD
       TimeOut 300

       ErrorLog ${APACHE_LOG_DIR}/firewall_monitor_error.log
       CustomLog ${APACHE_LOG_DIR}/firewall_monitor_access.log combined
   </VirtualHost>
   ```

4. **Habilitar sitio y módulos:**
   ```bash
   sudo a2enmod rewrite
   sudo a2ensite firewall-monitor.conf
   sudo systemctl reload apache2
   ```

---

### 4. Despliegue en Linux con Nginx + PHP-FPM

1. **Instalar Nginx y PHP-FPM:**
   ```bash
   sudo apt update
   sudo apt install -y nginx php8.2-fpm php8.2-mysql php8.2-curl php8.2-mbstring php8.2-intl mariadb-server
   ```

2. **Configurar bloque de servidor (`/etc/nginx/sites-available/firewall-monitor`):**
   ```nginx
   server {
       listen 80;
       server_name firewall-monitor.local;
       root /var/www/html/firewall-monitor;
       index index.php dashboard.php;

       client_max_body_size 50M;

       location / {
           try_files $uri $uri/ /index.php?$query_string;
       }

       # Bloquear acceso a archivos ocultos (.env, .git)
       location ~ /\. {
           deny all;
           access_log off;
           log_not_found off;
       }

       location ~ \.php$ {
           include snippets/fastcgi-php.conf;
           fastcgi_pass unix:/run/php/php8.2-fpm.sock;
           fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
           include fastcgi_params;

           # Evitar errores 504 Gateway Timeout en evaluaciones IA o limpieza masiva
           fastcgi_read_timeout 300s;
           proxy_read_timeout 300s;
       }
   }
   ```

3. **Activar la configuración y reiniciar:**
   ```bash
   sudo ln -s /etc/nginx/sites-available/firewall-monitor /etc/nginx/sites-enabled/
   sudo nginx -t
   sudo systemctl reload nginx
   ```

---

### 5. Despliegue en Windows con WAMP

1. **Instalar WampServer:** Descarga e instala WampServer 3.3+ (64-bit) con PHP 8.1+ y MariaDB/MySQL.
2. **Copiar proyecto:** Extrae la carpeta del proyecto dentro de `C:\wamp64\www\firewall-monitor`.
3. **Habilitar extensiones PHP:**
   - Haz clic izquierdo en el ícono de WAMP en la bandeja del sistema → **PHP** → **PHP Extensions**.
   - Verifica que estén marcadas: `php_curl`, `php_pdo_mysql`, `php_mbstring`, `php_openssl`, `php_intl`.
4. **Certificados SSL para cURL (Importante para Gemini API):**
   - Si las consultas a APIs HTTPS fallan por certificado SSL en Windows, descarga `cacert.pem` desde [curl.se/ca/cacert.pem](https://curl.se/ca/cacert.pem) y guárdalo en `C:\wamp64\bin\php\php8.x.x\extras\ssl\cacert.pem`.
   - Edita `php.ini` (desde el menú de WAMP → *PHP → php.ini*) y define:
     ```ini
     curl.cainfo = "C:\wamp64\bin\php\php8.x.x\extras\ssl\cacert.pem"
     openssl.cafile = "C:\wamp64\bin\php\php8.x.x\extras\ssl\cacert.pem"
     max_execution_time = 300
     ```
5. **Crear VirtualHost en WAMP:**
   - Abre `http://localhost` en el navegador → **Add a Virtual Host**.
   - Nombre: `firewall-monitor.local` | Ruta: `C:/wamp64/www/firewall-monitor`.
   - Reinicia todos los servicios de WAMP.

---

## Configuración de los Firewalls

Para que el sistema reciba y registre los eventos del firewall (permitidos y bloqueados, entrantes y salientes), habilita el reenvío de logs por **Syslog** o configura el acceso por **API/SSH** en cada firewall.

### Configuración en pfSense

#### Opción A: Envío de Logs Remotos (Syslog) hacia el Servidor
1. Ingresa a la interfaz web de pfSense y ve a **Status → System Logs → Settings**.
2. Desplázate hasta la sección **Remote Logging Options**:
   - Marca **Enable Remote Logging** (*Send log messages to remote syslog server*).
   - **Source Address:** Selecciona la interfaz LAN o VPN con conectividad hacia el servidor del sistema.
   - **IP Protocol:** `IPv4`.
   - **Remote log servers:** Ingresa `IP_DEL_SERVIDOR_MONITOR:514` (o el puerto configurado en tu receptor Syslog).
   - **Remote Syslog Contents:** Marca **Firewall Events** (obligatorio) y opcionalmente *System Events*.
3. Haz clic en **Save**.
4. En **Firewall → Rules**, asegúrate de tener activada la opción de registro (**Log**) en las reglas entrantes, salientes y de bloqueo que desees visualizar en los gráficos.

#### Opción B: Acceso por SSH / API para Importación Directa
1. Ve a **System → User Manager** y crea un usuario dedicado (ej. `auditor_logs`).
2. Asígnale permisos de lectura de logs (`WebCfg - Status: System Logs: Firewall` o acceso SSH de solo lectura a `/var/log/filter.log`).
3. Si utilizas autenticación por llave pública (recomendado), pega la llave pública RSA/Ed25519 del servidor web en **Authorized SSH Keys** del usuario.
4. En **Firewall → Rules → LAN** (o interfaz de gestión), permite el tráfico desde la IP del servidor hacia la IP del pfSense (puerto `22` SSH o `443` HTTPS).

---

### Configuración en OPNsense

#### Opción A: Envío de Logs Remotos (Syslog)
1. En el panel de OPNsense, navega a **System → Settings → Logging / targets**.
2. Haz clic en **+** (Añadir nuevo destino):
   - **Enabled:** Activado.
   - **Transport:** `UDP(4)` o `TCP(4)`.
   - **Applications:** Selecciona `filter` (Firewall filterlog).
   - **Levels:** `Informational`, `Notice`, `Warning`, `Error`.
   - **Hostname:** IP del servidor donde corre este sistema.
   - **Port:** `514` (o el puerto de tu receptor Syslog).
   - **Description:** `Visor Logs Firewall`.
3. Guarda y haz clic en **Apply**.
4. Verifica que en **Firewall → Rules** esté marcada la opción **Log packets matched by rule** en las reglas que quieras auditar en los gráficos.

#### Opción B: Acceso mediante API REST (Recomendado en OPNsense)
1. Ve a **System → Access → Users** y crea un usuario (ej. `api_monitor`).
2. En **Effective Privileges**, asígnale permisos de lectura sobre **Diagnostics: Logs: Firewall** y **Status: Interfaces**.
3. Guarda el usuario, vuelve a editarlo y en la sección **API keys** pulsa **+** para generar un par `key` y `secret` (se descargará un archivo `.txt` con ambas credenciales).
4. Verifica que en **Firewall → Rules** de la interfaz de administración se permita el acceso HTTPS (`443`) desde la IP del servidor del sistema.

---

## Registro de Firewalls en el Sistema

Una vez configurado pfSense u OPNsense, registra el equipo dentro de la aplicación web:

1. Inicia sesión en la plataforma y dirígete al menú lateral izquierdo: **Administración → Configurar Firewalls** (`firewalls.php`).
2. Haz clic en **Agregar Firewall** (o completa el formulario de alta) con los siguientes datos:
   - **Nombre Identificador:** Nombre corto del nodo o sucursal (ej. `FW-Central`, `MCC`, `Sucursal-Norte`). Este nombre aparecerá en los gráficos, filtros y alertas.
   - **Tipo / Plataforma:** Selecciona `pfSense` u `OPNsense`.
   - **Dirección IP / Host:** IP de gestión del firewall accesible desde el servidor web (ej. `192.168.1.1`).
   - **Puerto:** `22` (para recolección por SSH/SCP) o `443` (para consulta vía API).
   - **Credenciales de Acceso:**
     - *Para SSH:* Usuario y contraseña o ruta a la llave privada.
     - *Para OPNsense API:* `API Key` y `API Secret` generados en el paso anterior.
   - **Estado:** `Activo`.
3. Guarda los cambios y ejecuta una prueba desde **Administración → Importar Firewall** (`import_firewall.php`) para confirmar que los eventos entrantes, salientes y bloqueados (`PASS` / `BLOCK`) se almacenan correctamente en `firewall_eventos`.
4. Desde **Administración → Configurar Seguridad** (`configuracion_seguridad.php`) podrás definir los **puertos de especial interés** que deseas vigilar prioritariamente en el dashboard.

---

## Tareas Programadas (Cron), Permisos de `tmp` y SELinux

### Configuración de Cron

Para consultar y recolectar automáticamente los registros desde los firewalls configurados cada 10 minutos, agrega la siguiente tarea en el `crontab` del usuario correspondiente (o root/usuario del servicio):

```cron
*/10 * * * * /usr/bin/php /ruta/al/firewall/cron_importar_logs.php >> /ruta/al/firewall/tmp/cron_output.log 2>&1
```

Puedes editar el `crontab` con:

```bash
crontab -e
```
*(Si deseas ejecutarla bajo un usuario específico como `apache` o `www-data`, usa `sudo crontab -u www-data -e`).*

### Permisos de la Carpeta `tmp` y Logs

Crea el directorio `tmp` y el archivo `cron_output.log` si aún no existen, y asigna permisos adecuados para que tanto el proceso de `cron` como el servidor web puedan escribir los registros sin fallos de permiso:

```bash
sudo mkdir -p /ruta/al/firewall/tmp
sudo touch /ruta/al/firewall/tmp/cron_output.log
sudo chown -R apache:apache /ruta/al/firewall/tmp
sudo chmod -R 775 /ruta/al/firewall/tmp
sudo chmod 664 /ruta/al/firewall/tmp/cron_output.log
```
*(En sistemas basados en Debian/Ubuntu con Apache o Nginx/PHP-FPM, reemplaza `apache:apache` por `www-data:www-data`).*

### Configuración de SELinux

En distribuciones con **SELinux** habilitado en modo *Enforcing* (como RHEL, Rocky Linux, AlmaLinux o CentOS Stream), el servidor web y los scripts PHP pueden verse bloqueados al escribir en `tmp`, conectarse a bases de datos remotas o realizar conexiones salientes por red (por ejemplo hacia el nodo local de Ollama o la API de Gemini).

1. **Verificar el estado de SELinux:**
   ```bash
   sestatus
   ```

2. **Asignar contexto de lectura/escritura (`httpd_sys_rw_content_t`) a la carpeta `tmp` y al log:**
   ```bash
   sudo semanage fcontext -a -t httpd_sys_rw_content_t "/ruta/al/firewall/tmp(/.*)?"
   sudo restorecon -Rv /ruta/al/firewall/tmp
   ```

3. **Permitir conexiones de red desde HTTPD / PHP (necesario para consultas API/IA y conexiones remotas):**
   ```bash
   sudo setsebool -P httpd_can_network_connect 1
   ```
   Si también el servidor web necesita conectarse a una base de datos MySQL/MariaDB en red (o por TCP):
   ```bash
   sudo setsebool -P httpd_can_network_connect_db 1
   ```

4. **Revisar denegaciones de SELinux si persiste algún bloqueo:**
   ```bash
   sudo ausearch -m avc -ts recent
   ```

---

## Mantenimiento de Base de Datos

Para mantener el rendimiento óptimo de los gráficos y consultas sin crecimiento desmedido de `firewall_eventos`:

* **Limpieza Manual desde la Web:** Accede a **Administración → Mantenimiento BD** (`mantenimiento_bd.php`) para eliminar por lotes los registros históricos antiguos o ya auditados.
* **Compactación Física en Disco (CLI):** Tras realizar depuraciones masivas en MariaDB/InnoDB, puedes reclamar espacio físico ejecutando por consola:
  ```bash
  mysql -u fw_monitor -p firewall_logs -e "OPTIMIZE TABLE firewall_eventos;"
  ```

---

## Licencia

Este proyecto se distribuye bajo los términos de la **Licencia Apache, Versión 2.0** (`Apache-2.0`). Consulta el archivo [LICENSE](LICENSE) en la raíz del repositorio para conocer los detalles completos sobre permisos, condiciones y limitaciones de responsabilidad.
