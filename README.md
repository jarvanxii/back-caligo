# Caligo Backend

Backend Spring Boot de Caligo. Expone una API REST con JWT, Flyway y MariaDB para ejecutar herramientas de laboratorio de ciberseguridad en entornos controlados.

Los modulos funcionales actuales son **URLs**, **Reconocimiento activo**, **Metasploit** y **Fuerza bruta controlada**. URLs cubre DNS, inspeccion URL, HTTP, TLS, reputacion, historial, archivos publicos, endpoints pasivos e inventario de herramientas locales. Reconocimiento activo cubre jobs de **Nmap** y adaptador **OpenVAS/GVM** con JWT, auditoria, validacion de alcance y progreso. Metasploit expone RPC local para discovery asistido, recomendaciones de modulos, ejecucion controlada y gestion de sesiones de laboratorio. Fuerza bruta integra **Hydra** con alcance privado/local, fuentes de credenciales del servidor y trazas redaccionadas.
El panel de sistema expone inventario versionado de herramientas instaladas y actualizaciones controladas por allowlist.

## Stack

- Java 21.
- Spring Boot 3.3.5.
- Maven.
- Spring Web.
- Spring Security.
- JJWT 0.12.6.
- Spring Data JPA + Hibernate.
- MariaDB.
- Flyway (`flyway-core` + `flyway-mysql`).
- MariaDB JDBC Driver.
- Spring Validation.
- Spring Actuator.
- Nmap CLI en el servidor.
- Greenbone/OpenVAS via `gvm-cli` cuando GVM esta inicializado.
- Metasploit Framework via MessagePack RPC (`msgrpc`) escuchando solo en localhost.
- Hydra CLI para simulaciones de fuerza bruta en laboratorio.

## Estructura

```text
back-caligo/
  compose.yml
  pom.xml
  src/main/java/com/caligo/backend/
    auth/          Login, registro y DTOs de autenticacion
    audit/         Eventos de auditoria
    bruteforce/    Integracion Hydra, capacidades, jobs y parseo de credenciales
    common/        Manejo comun de errores REST
    config/        Seguridad, CORS, filtro JWT y bootstrap admin
    health/        Endpoints de salud
    module/        Catalogo de modulos visibles
    metasploit/   Cliente RPC, recomendaciones, ejecucion de modulos y sesiones
    recon/         Jobs Nmap/OpenVAS, capacidades, progreso y parseo de resultados
    security/      JWT y UserDetailsService
    system/        Inventario y actualizacion controlada de herramientas del servidor
    urls/          Motor de inteligencia URL/DNS/HTTP/TLS
    user/          Usuarios, roles y endpoint /api/me
  src/main/resources/
    application.yml
    db/migration/
      V1__init_schema.sql
      V2__url_intelligence.sql
      V3__nmap_module.sql
      V4__tool_execution_jobs.sql
```

## Base de datos

La base oficial del proyecto es **MariaDB**. No se usa PostgreSQL ni H2.

Conexion local por defecto:

```text
Host: localhost
Puerto: 3306
Base de datos: caligo
Usuario: root
Password: definido por CALIGO_DB_PASSWORD
JDBC: jdbc:mariadb://localhost:3306/caligo
```

Los secretos reales de local/servidor no se versionan. Estan fuera del repo, en `C:\Users\Jarva\Desktop\AGENTS\CREDENCIALES.MD`.

Spring ejecuta Flyway al arrancar. Hibernate queda con `ddl-auto=validate`, por lo que las migraciones SQL son la fuente de verdad.

### Arranque local con Docker

```powershell
cd C:\Users\Jarva\Desktop\git-repos\back-caligo
$env:CALIGO_DB_ROOT_PASSWORD="<password-local-de-CREDENCIALES>"
$env:CALIGO_DB_PASSWORD="<password-local-de-CREDENCIALES>"
docker compose up -d
mvn spring-boot:run
```

Si Maven no usa Java 21:

```powershell
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
```

API local por defecto:

```text
http://localhost:8080
```

## Variables

| Variable | Default local | Uso |
| --- | --- | --- |
| `CALIGO_DB_URL` | `jdbc:mariadb://localhost:3306/caligo` | JDBC MariaDB. |
| `CALIGO_DB_USER` | `root` | Usuario de base de datos. |
| `CALIGO_DB_PASSWORD` | vacio | Password de base de datos. Debe venir de entorno. |
| `CALIGO_LOGIN_RESPONSE_DELAY_MILLIS` | `2000` | Retraso fijo aplicado a cada intento de login para reducir fuerza bruta. |
| `CALIGO_JWT_SECRET` | secreto local inseguro | Firma HMAC de JWT. Cambiar fuera de local. |
| `CALIGO_JWT_EXPIRATION_MINUTES` | `60` | Duracion del token. |
| `CALIGO_BOOTSTRAP_ADMIN_USER` | `admin` | Admin inicial si no hay usuarios. |
| `CALIGO_BOOTSTRAP_ADMIN_EMAIL` | `admin@caligo.local` | Email admin inicial. |
| `CALIGO_BOOTSTRAP_ADMIN_PASSWORD` | `change-me-now` | Password admin local. |
| `CALIGO_SERVER_PORT` | `8080` | Puerto HTTP. |
| `CALIGO_CORS_ALLOWED_ORIGINS` | front local Vite | Origenes permitidos. |
| `CALIGO_VIRUSTOTAL_API_KEY` | sin configurar | Activa consulta VirusTotal. |
| `CALIGO_ABUSEIPDB_API_KEY` | sin configurar | Activa reputacion IP con AbuseIPDB. |
| `CALIGO_SAFE_BROWSING_API_KEY` | sin configurar | Activa Google Safe Browsing. |
| `CALIGO_RECON_ALLOW_EXTERNAL_TARGETS` | `false` | Si `false`, Nmap/OpenVAS solo aceptan objetivos privados/locales. |
| `CALIGO_RECON_MAX_OUTPUT_BYTES` | `1048576` | Limite de salida capturada por proceso. |
| `CALIGO_NMAP_BINARY` | `nmap` | Binario Nmap. |
| `CALIGO_NMAP_TIMEOUT_SECONDS` | `900` | Timeout por job Nmap. |
| `CALIGO_GVM_CLI` | `gvm-cli` | Binario gvm-cli. |
| `CALIGO_GVM_SOCKET` | `/run/gvmd/gvmd.sock` | Socket GMP de gvmd. |
| `CALIGO_GVM_USERNAME` | sin configurar | Usuario GMP/OpenVAS. |
| `CALIGO_GVM_PASSWORD` | sin configurar | Password GMP/OpenVAS. |
| `CALIGO_GVM_POLL_SECONDS` | `10` | Intervalo de polling de tareas OpenVAS. |
| `CALIGO_GVM_TIMEOUT_SECONDS` | `7200` | Timeout maximo de job OpenVAS. |
| `CALIGO_BRUTEFORCE_ALLOW_EXTERNAL_TARGETS` | `false` | Si `false`, Hydra solo acepta objetivos privados/locales. |
| `CALIGO_BRUTEFORCE_MAX_OUTPUT_BYTES` | `1048576` | Limite de salida capturada por proceso Hydra. |
| `CALIGO_HYDRA_BINARY` | `hydra` | Binario Hydra. |
| `CALIGO_HYDRA_TIMEOUT_SECONDS` | `1800` | Timeout maximo de job Hydra. |
| `CALIGO_HYDRA_WORDLIST_ROOTS` | `/opt/caligo/wordlists,/usr/share/wordlists` | Raices permitidas para wordlists del servidor. |
| `CALIGO_MSF_RPC_HOST` | `127.0.0.1` | Host local del RPC MessagePack de Metasploit. |
| `CALIGO_MSF_RPC_PORT` | `55552` | Puerto local del plugin `msgrpc`. |
| `CALIGO_MSF_RPC_SSL` | `false` | Debe coincidir con el modo SSL del plugin `msgrpc`. |
| `CALIGO_MSF_RPC_USER` | `caligo` | Usuario RPC de Metasploit. |
| `CALIGO_MSF_RPC_PASSWORD` | sin configurar | Password RPC generada fuera del repo. |
| `CALIGO_MSF_RPC_TIMEOUT_SECONDS` | `20` | Timeout de llamadas RPC. |
| `CALIGO_SYSTEM_TOOL_UPDATE_TIMEOUT_SECONDS` | `900` | Timeout maximo por paso de actualizacion de herramientas. |

## Esquema MariaDB

### `users`

| Columna | Tipo | Uso |
| --- | --- | --- |
| `id` | `char(36)` | UUID primario. |
| `username` | `varchar(80)` | Usuario unico. |
| `email` | `varchar(160)` | Email unico. |
| `password_hash` | `varchar(255)` | Password cifrada con BCrypt. |
| `role` | `varchar(30)` | `ADMIN`, `OPERATOR`, `VIEWER`. |
| `active` | `boolean` | Activa o bloquea el usuario. |
| `created_at` | `datetime(6)` | Alta. |
| `updated_at` | `datetime(6)` | Ultima actualizacion. |

### `tool_modules`

Catalogo de modulos visibles desde el frontend.

| Columna | Tipo | Uso |
| --- | --- | --- |
| `id` | `char(36)` | UUID primario. |
| `code` | `varchar(60)` | Codigo unico del modulo. |
| `display_name` | `varchar(120)` | Nombre visible. |
| `description` | `varchar(500)` | Descripcion corta. |
| `enabled` | `boolean` | Control de visibilidad. |
| `created_at` | `datetime(6)` | Alta. |

Modulos iniciales: `urls`, `nmap`, `openvas`, `metasploit`, `bruteforce`, `passwords`, `encoding`, `steganography`.

### `audit_events`

Auditoria minima para acciones sensibles.

| Columna | Tipo | Uso |
| --- | --- | --- |
| `id` | `char(36)` | UUID primario. |
| `username` | `varchar(80)` | Usuario autenticado. |
| `action` | `varchar(120)` | Accion realizada. |
| `target` | `varchar(240)` | Recurso analizado o afectado. |
| `ip_address` | `varchar(80)` | IP origen. |
| `created_at` | `datetime(6)` | Fecha. |

### `url_analysis_jobs`

Historial local de analisis del modulo URLs.

| Columna | Tipo | Uso |
| --- | --- | --- |
| `id` | `char(36)` | UUID primario. |
| `username` | `varchar(80)` | Usuario que lanza el analisis. |
| `input_target` | `varchar(1000)` | Entrada original. |
| `normalized_url` | `varchar(1200)` | URL normalizada. |
| `host` | `varchar(255)` | Host analizado. |
| `mode` | `varchar(40)` | Herramienta o modo ejecutado. |
| `risk_score` | `integer` | Score 0-100. |
| `verdict` | `varchar(80)` | Lectura humana del score. |
| `private_network_allowed` | `boolean` | Permiso para rangos privados. |
| `duration_ms` | `integer` | Duracion. |
| `result_json` | `text` | Resultado serializado. |
| `created_at` | `datetime(6)` | Fecha. |

### `tool_execution_jobs`

Historial y trazabilidad de herramientas activas.

| Columna | Tipo | Uso |
| --- | --- | --- |
| `id` | `char(36)` | UUID primario del job. |
| `username` | `varchar(80)` | Usuario que lanza la herramienta. |
| `tool` | `varchar(40)` | `nmap`, `openvas`, `metasploit` o `hydra`. |
| `target` | `varchar(240)` | Objetivo validado. |
| `status` | `varchar(30)` | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`. |
| `progress` | `integer` | Progreso 0-100. |
| `phase` | `varchar(160)` | Fase visible para el frontend. |
| `parameters_json` | `text` | Parametros recibidos. |
| `result_json` | `longtext` | Resultado normalizado. |
| `error_message` | `text` | Error tecnico si falla. |
| `command_preview` | `varchar(1200)` | Comando o resumen sin secretos. |
| `started_at` | `datetime(6)` | Inicio real. |
| `completed_at` | `datetime(6)` | Fin real. |
| `created_at` | `datetime(6)` | Alta. |
| `updated_at` | `datetime(6)` | Ultima actualizacion. |

Todas las tablas usan `InnoDB`, `utf8mb4` y collation `utf8mb4_unicode_ci`.

## JWT

Login local:

```powershell
$body = @{
  username = "Gandalf"
  password = "<password-del-entorno>"
} | ConvertTo-Json

$response = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8080/api/auth/login" `
  -ContentType "application/json" `
  -Body $body

$token = $response.accessToken
```

El servidor 2 tiene `Gandalf` creado en MariaDB con `password_hash` BCrypt. La contraseña operativa no se versiona. Los registros nuevos usan el mismo `PasswordEncoder` del endpoint de registro.

Llamada protegida:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:8080/api/modules" `
  -Headers @{ Authorization = "Bearer $token" }
```

## Endpoints principales

| Metodo | Ruta | JWT | Descripcion |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Health publico. |
| `GET` | `/actuator/health` | No | Health Actuator. |
| `POST` | `/api/auth/login` | No | Login. |
| `POST` | `/api/auth/register` | No | Registro temporal local. |
| `GET` | `/api/me` | Si | Perfil autenticado. |
| `GET` | `/api/modules` | Si | Modulos habilitados. |
| `GET` | `/api/system/tools` | Si | Inventario de herramientas del servidor, version, path y gestor. |
| `POST` | `/api/system/tools/{id}/update` | Si, ADMIN | Actualiza una herramienta allowlisted desde el servidor. |
| `GET` | `/api/urls/local-tools` | Si | Inventario de herramientas locales instaladas. |
| `POST` | `/api/urls/dns-resolver` | Si | DNS: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `CAA`. |
| `POST` | `/api/urls/inspector` | Si | Normalizacion e indicadores URL. |
| `POST` | `/api/urls/http-security` | Si | Status, redirecciones, cabeceras y cookies. |
| `POST` | `/api/urls/tls-certificate` | Si | Certificado, SANs, emisor, validez y fingerprint. |
| `POST` | `/api/urls/reputation` | Si | URLHaus, urlscan.io y fuentes opcionales con API key. |
| `POST` | `/api/urls/history` | Si | RDAP, crt.sh y Wayback. |
| `POST` | `/api/urls/public-files` | Si | `robots.txt`, `sitemap.xml`, `security.txt` y well-known. |
| `POST` | `/api/urls/endpoints` | Si | Extraccion pasiva de enlaces, scripts y formularios. |
| `POST` | `/api/urls/intelligent-analysis` | Si | Analisis inteligente agregado. |
| `GET` | `/api/urls/analyses` | Si | Ultimos analisis del usuario. |
| `GET` | `/api/urls/analyses/{id}` | Si | Resultado guardado. |
| `GET` | `/api/recon/nmap/capabilities` | Si | Perfiles, timing, modos de puerto y estado del binario Nmap. |
| `POST` | `/api/recon/nmap/scans` | Si | Crea job Nmap. |
| `GET` | `/api/recon/nmap/scans/{id}` | Si | Estado, progreso y resultado Nmap. |
| `GET` | `/api/recon/nmap/scans/{id}/report.pdf` | Si | Informe PDF descargable con logo Caligo. |
| `GET` | `/api/recon/openvas/capabilities` | Si | Estado GVM, perfiles, port lists y alive tests. |
| `POST` | `/api/recon/openvas/scans` | Si | Crea tarea OpenVAS via GMP si GVM esta listo. |
| `GET` | `/api/recon/openvas/scans/{id}` | Si | Estado, progreso y hallazgos OpenVAS. |
| `GET` | `/api/recon/openvas/scans/{id}/report.pdf` | Si | Informe PDF descargable con logo Caligo. |
| `GET` | `/api/bruteforce/hydra/capabilities` | Si | Estado Hydra, servicios soportados, modos de credenciales y wordlists permitidas. |
| `POST` | `/api/bruteforce/hydra/runs` | Si | Crea job Hydra con alcance validado y credenciales redaccionadas en preview/logs. |
| `GET` | `/api/bruteforce/hydra/runs` | Si | Ultimos jobs Hydra del usuario. |
| `GET` | `/api/bruteforce/hydra/runs/{id}` | Si | Estado, progreso, logs y credenciales validas encontradas por Hydra. |
| `GET` | `/api/metasploit/capabilities` | Si | Estado RPC, payloads por defecto y politica de alcance. |
| `POST` | `/api/metasploit/recommendations` | Si | Genera recomendaciones de modulos desde hosts/puertos detectados. |
| `GET` | `/api/metasploit/module-catalog` | Si | Busca modulos por texto y tipo. |
| `GET` | `/api/metasploit/module-search` | Si | Alias compatible para catalogo de modulos. |
| `GET` | `/api/metasploit/modules/search` | Si | Alias compatible para busqueda de modulos. |
| `GET` | `/api/metasploit/modules/info` | Si | Info, opciones y payloads compatibles de un modulo. |
| `POST` | `/api/metasploit/modules/execute` | Si | Ejecuta un modulo via RPC con datastore validado. |
| `GET` | `/api/metasploit/jobs` | Si | Jobs vivos en Metasploit. |
| `GET` | `/api/metasploit/jobs/{id}` | Si | Job guardado por Caligo. |
| `GET` | `/api/metasploit/sessions` | Si | Sesiones activas. |
| `POST` | `/api/metasploit/sessions/{id}/command` | Si | Envia comando a sesion shell o meterpreter. |
| `POST` | `/api/metasploit/sessions/{id}/workspace` | Si | Carga contexto grafico inicial de una sesion Meterpreter. |
| `POST` | `/api/metasploit/sessions/{id}/fs/list` | Si | Lista directorios remotos mediante Meterpreter. |
| `POST` | `/api/metasploit/sessions/{id}/fs/read` | Si | Lee una muestra truncada de un fichero remoto. |
| `POST` | `/api/metasploit/sessions/{id}/fs/mkdir` | Si | Crea un directorio remoto y refresca el listado. |
| `POST` | `/api/metasploit/sessions/{id}/fs/delete` | Si | Borra fichero o directorio vacio remoto. |
| `POST` | `/api/metasploit/sessions/{id}/fs/rename` | Si | Renombra o mueve una ruta remota. |
| `DELETE` | `/api/metasploit/sessions/{id}` | Si | Cierra una sesion. |

Peticion URL:

```json
{
  "target": "https://example.com",
  "allowPrivateNetworks": false
}
```

`allowPrivateNetworks` debe usarse solo en laboratorios locales autorizados. Si esta a `false`, el backend bloquea destinos privados, loopback, link-local y rangos internos para reducir riesgo SSRF.

## Reconocimiento activo

### Nmap

`POST /api/recon/nmap/scans` acepta:

```json
{
  "target": "192.168.0.1",
  "profile": "standard",
  "scanType": "tcp-connect",
  "portMode": "top",
  "topPorts": 1000,
  "timing": "T3",
  "serviceDetection": true,
  "defaultScripts": false,
  "osDetection": false,
  "traceroute": false,
  "noPing": false,
  "maxRetries": 2
}
```

El backend ejecuta Nmap con `ProcessBuilder`, no con shell. Por defecto bloquea objetivos publicos y solo permite rangos privados/locales como `192.168.0.0/24`, `10.0.0.5`, `127.0.0.1` o `host.local`. El progreso se extrae de `--stats-every 5s` cuando Nmap lo emite.

Las opciones `OS detect` y `Traceroute` necesitan privilegios de red. No se
hardcodean credenciales ni se usa sudo desde la aplicacion; el servidor debe
dar capabilities al binario Nmap:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$(command -v nmap)"
getcap "$(command -v nmap)"
```

Cuando esas opciones estan activas, el backend anade `--privileged` para que
Nmap use esas capabilities sin ejecutar el proceso como root.

Si el servicio systemd bloquea la herencia de capabilities, crear este override:

```bash
sudo mkdir -p /etc/systemd/system/caligo-back.service.d
sudo tee /etc/systemd/system/caligo-back.service.d/20-nmap-capabilities.conf >/dev/null <<'EOF'
[Service]
NoNewPrivileges=false
EOF
sudo systemctl daemon-reload
sudo systemctl restart caligo-back
```

El servicio sigue ejecutandose como `fran`; no hay password hardcodeada ni sudo
desde el backend.

Cada job Nmap puede exportarse a PDF. El informe incluye el logo de login de Caligo desde `src/main/resources/reports/logo-login.png`, parametros, resumen, puertos, servicios y salida tecnica relevante.

### OpenVAS/GVM

`POST /api/recon/openvas/scans` acepta:

```json
{
  "target": "192.168.0.50",
  "profile": "Full and fast",
  "portList": "All IANA assigned TCP",
  "aliveTest": "Scan Config Default"
}
```

OpenVAS se controla mediante `gvm-cli socket` contra `gvmd`. Para arrancar jobs reales hacen falta:

- `gvm`, `gvmd`, `openvas-scanner`, `ospd-openvas` y `gvm-tools` instalados.
- Feeds Greenbone sincronizados.
- Datos GVMD importados en base interna: scan configs y port lists no pueden estar vacios.
- Socket `gvmd` disponible.
- `CALIGO_GVM_USERNAME` y `CALIGO_GVM_PASSWORD` definidos fuera del repo.

La base de datos oficial de Caligo sigue siendo MariaDB. Greenbone/GVM instala y usa PostgreSQL como dependencia interna de su propio motor; eso no cambia la base de datos de la aplicacion.

Cada job OpenVAS puede exportarse a PDF. El informe incluye logo Caligo, parametros GMP, IDs de tarea/reporte, resumen por severidad y detalle priorizado de hallazgos.

Si `GET /api/recon/openvas/capabilities` indica `gvmd-data-incompleto`, reparar Greenbone en el servidor:

```bash
sudo -u _gvm greenbone-feed-sync --type scan-config --type port-list --no-wait
sudo -u _gvm gvmd --get-users --verbose
sudo -u _gvm gvmd --modify-setting 78eceaec-3385-11ea-b237-28d24461215b --value <uuid-usuario-gvm>
sudo -u _gvm gvmd --rebuild-gvmd-data=all --feed-lock-timeout=120
sudo systemctl restart gvmd
```

El backend solo marca OpenVAS como `ready` cuando GVM devuelve al menos una scan config, una port list y un scanner OpenVAS utilizable. El scanner `CVE` se filtra para evitar crear tareas normales con un motor incorrecto.

En el servidor 2, los logs de sincronizacion de feeds se dejan en:

```text
/var/log/caligo/gvm-feed-sync.log
```

### Hydra

`POST /api/bruteforce/hydra/runs` acepta:

```json
{
  "target": "192.168.0.10",
  "service": "ssh",
  "port": 22,
  "usernameMode": "single",
  "username": "hacker",
  "passwordMode": "list",
  "passwords": "password\npassword123\npepito53",
  "tasks": 4,
  "connectTimeoutSeconds": 10,
  "responseWaitSeconds": 5,
  "stopOnFound": true
}
```

Modos de usuario: `single`, `list`, `file`. Modos de password: `single`,
`list`, `file`, `combo`. El modo `combo` usa lineas `login:password` y se
traduce a `hydra -C`.

Servicios iniciales soportados: `ssh`, `ftp`, `telnet`, `smtp`, `pop3`, `imap`,
`smb`, `rdp`, `vnc`, `mysql`, `postgres`, `mssql`, `redis`, `mongodb`, `ldap2`,
`ldap3`, `http-get`, `https-get`, `http-head`, `https-head`,
`http-post-form`, `https-post-form`, `http-get-form` y `https-get-form`.

Para formularios HTTP se usan `httpPath`, `httpParameters`,
`httpFailCondition` y `httpSuccessCondition`. `httpParameters` debe incluir
`^USER^` y `^PASS^`, por ejemplo:

```json
{
  "service": "http-post-form",
  "httpPath": "/login",
  "httpParameters": "username=^USER^&password=^PASS^",
  "httpFailCondition": "F=incorrect"
}
```

El backend ejecuta Hydra con `ProcessBuilder`, no con shell. Por defecto bloquea
objetivos publicos y solo permite hosts privados/locales como `192.168.0.10`,
`10.0.0.5`, `127.0.0.1` o `host.local`. Las listas pegadas se escriben en
ficheros temporales para evitar passwords en argumentos de proceso, y esos
ficheros se eliminan al terminar. `command_preview`, parametros guardados y
logs en vivo redaccionan passwords; el resultado final conserva solo las
credenciales validas encontradas para que la herramienta sea util en el
laboratorio.

Wordlists permitidas por defecto:

```text
/opt/caligo/wordlists
/usr/share/wordlists
```

En el servidor se deja un set minimo de laboratorio en:

```text
/opt/caligo/wordlists/users-basic.txt
/opt/caligo/wordlists/passwords-basic.txt
```

### Metasploit

Caligo usa la API MessagePack de Metasploit mediante el plugin `msgrpc`. El
servicio debe quedar vinculado a `127.0.0.1`, con credenciales generadas fuera
del repo y leidas por el backend desde `/etc/caligo/back.env`.

Instalacion recomendada en Linux:

```bash
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
sudo ./msfinstall
```

Se evita pasar la password como argumento de proceso. Para ello se crea un
resource file protegido:

```text
/etc/caligo/msgrpc.rc
```

Contenido esperado del resource file, con password real fuera de Git:

```text
load msgrpc ServerHost=127.0.0.1 ServerPort=55552 User=caligo Pass=<password-random-local> SSL=false
sleep 31536000
```

Servicio systemd esperado:

```ini
[Unit]
Description=Metasploit RPC for Caligo
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=fran
Group=www-data
WorkingDirectory=/home/fran
EnvironmentFile=/etc/caligo/back.env
Environment=DISABLE_BOOTSNAP=1
ExecStart=/usr/bin/msfconsole -q -n -r /etc/caligo/msgrpc.rc
Restart=on-failure
RestartSec=8
NoNewPrivileges=true
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Variables minimas:

```bash
CALIGO_MSF_RPC_HOST=127.0.0.1
CALIGO_MSF_RPC_PORT=55552
CALIGO_MSF_RPC_SSL=false
CALIGO_MSF_RPC_USER=caligo
CALIGO_MSF_RPC_PASSWORD=<password-random-local>
```

La API bloquea objetivos publicos y solo acepta hosts privados/locales para
Metasploit. Las llamadas quedan auditadas (`METASPLOIT_MODULE_EXECUTE`,
`METASPLOIT_SESSION_COMMAND`, `METASPLOIT_SESSION_WORKSPACE`,
`METASPLOIT_SESSION_FILE_LIST`, `METASPLOIT_SESSION_FILE_READ`,
`METASPLOIT_SESSION_MKDIR`, `METASPLOIT_SESSION_FILE_DELETE`,
`METASPLOIT_SESSION_FILE_RENAME`, `METASPLOIT_SESSION_STOP`) y el backend no usa
sudo ni credenciales hardcodeadas. Para pruebas manuales desde el front, primero
lanza discovery Nmap, revisa las recomendaciones y despues ejecuta un modulo
contra una maquina vulnerable de laboratorio.

El explorador grafico solo se habilita sobre sesiones Meterpreter. Desde esa
sesion permite listar rutas, leer muestras de ficheros, crear carpetas,
renombrar/mover rutas, borrar ficheros o directorios vacios y ejecutar comandos
en consola. Las rutas remotas se validan para evitar saltos de linea,
metacaracteres de shell y entradas excesivamente largas.

## Herramientas de servidor

El inventario de URLs detecta estas herramientas cuando existen en `PATH`:

- `curl`
- `openssl`
- `whois`
- `dig`
- `nslookup`
- `httpx`
- `nuclei`
- `katana`
- `gau`
- `subfinder`
- `amass`
- `ffuf`

Herramientas instaladas en el servidor 2 durante el primer despliegue: `nmap`, `ffuf`, `john`, `hashcat`, `exiftool`, `steghide`, `binwalk`, `zsteg`, `httpx`, `nuclei`, `katana`, `gau`, `subfinder` y `amass`.

Herramientas instaladas para reconocimiento activo: `nmap`, `gvm`, `gvmd`, `openvas-scanner`, `ospd-openvas` y `gvm-tools`. Las herramientas activas deben ejecutarse siempre con alcance autorizado, trazabilidad, limites y registro de usuario.

Herramientas instaladas para validacion controlada: `metasploit-framework` con
`msgrpc` gestionado por systemd y expuesto solo en localhost.

Herramientas instaladas para fuerza bruta controlada: `hydra`. Las wordlists de
laboratorio de Caligo viven en `/opt/caligo/wordlists` y las wordlists del
sistema se leen solo si estan bajo las raices permitidas por
`CALIGO_HYDRA_WORDLIST_ROOTS`.

### Actualizaciones desde Caligo

El endpoint `GET /api/system/tools` devuelve el inventario del servidor con
version actual, binario detectado, grupo funcional y gestor (`apt`, `go` o
`gem`). El frontend lo usa en `Ajustes > Actualizaciones`.

El endpoint `POST /api/system/tools/{id}/update` solo acepta IDs definidos en el
backend. No recibe comandos desde el navegador y requiere rol `ADMIN`. Cada
accion se audita como `SYSTEM_TOOL_UPDATE_START`, `SYSTEM_TOOL_UPDATE_SUCCESS`
o `SYSTEM_TOOL_UPDATE_FAILED`.

Los updates usan comandos estaticos:

- Paquetes APT: `sudo -n apt-get update` y `sudo -n apt-get install --only-upgrade -y <paquete>`.
- Herramientas Go: `go install <modulo>@latest`.
- Gems: `sudo -n gem update <gem>`.

Para que APT/Gem funcionen desde el servicio sin hardcodear passwords, el
servidor debe conceder `NOPASSWD` solo a los comandos de mantenimiento
permitidos para el usuario del servicio. Si no existe ese permiso, el endpoint
devuelve el fallo de `sudo -n` en la salida de la operacion y no queda bloqueado.

## Despliegue servidor

Servidor asignado: `192.168.0.253`.

Rutas:

```text
/var/www/caligo/back
/etc/caligo/back.env
```

Variables minimas en `/etc/caligo/back.env`:

```bash
CALIGO_DB_URL=jdbc:mariadb://localhost:3306/caligo
CALIGO_DB_USER=root
CALIGO_DB_PASSWORD=<password-servidor-de-CREDENCIALES>
CALIGO_JWT_SECRET=<secreto-largo>
CALIGO_CORS_ALLOWED_ORIGINS=http://localhost:5174,http://127.0.0.1:5174,http://192.168.0.17:5174
CALIGO_SERVER_PORT=8080
CALIGO_MSF_RPC_HOST=127.0.0.1
CALIGO_MSF_RPC_PORT=55552
CALIGO_MSF_RPC_SSL=false
CALIGO_MSF_RPC_USER=caligo
CALIGO_MSF_RPC_PASSWORD=<password-random-local>
CALIGO_HYDRA_BINARY=hydra
CALIGO_HYDRA_WORDLIST_ROOTS=/opt/caligo/wordlists,/usr/share/wordlists
CALIGO_SYSTEM_TOOL_UPDATE_TIMEOUT_SECONDS=900
```

No guardar este archivo en Git.

## Verificacion

Compilar y empaquetar:

```powershell
mvn -DskipTests package
```

Tests:

```powershell
mvn test
```

Prueba rapida:

```powershell
Invoke-RestMethod http://localhost:8080/api/health
```
