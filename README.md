# Caligo Backend

Backend Spring Boot de Caligo. Expone una API REST con JWT, Flyway y MariaDB para ejecutar herramientas de laboratorio de ciberseguridad en entornos controlados.

Los modulos funcionales actuales son **URLs**, **Reconocimiento activo**, **OSINT**, **Metasploit**, **Fuerza bruta controlada** y **Contrasenas**. URLs cubre DNS, inspeccion URL, HTTP, TLS, reputacion, historial, archivos publicos, endpoints pasivos e inventario de herramientas locales. Reconocimiento activo cubre jobs de **Nmap** y adaptador **OpenVAS/GVM** con JWT, auditoria, validacion de alcance y progreso. OSINT integra **Caligo People**, **Sherlock**, **Maigret**, **Social Analyzer**, **Holehe**, **theHarvester**, **git-dumper**, **SpiderFoot**, **TruffleHog** y utilidades de exposicion autorizada para emails, telefonos aportados, contactos de dominio, passwords y documentos publicos. Metasploit expone RPC local para discovery asistido, recomendaciones de modulos, ejecucion controlada y gestion de sesiones de laboratorio. Fuerza bruta integra **Hydra** con alcance privado/local, fuentes de credenciales del servidor y trazas redaccionadas. Contrasenas integra **John the Ripper**, **Hashcat**, **hashID**, **Crunch**, **CeWL** y wordlists permitidas del servidor.
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
- Sherlock, Maigret, Social Analyzer, Holehe, theHarvester, git-dumper, SpiderFoot y TruffleHog instalados en el servidor para OSINT.
- Endpoints OSINT server-side para Email Exposure, Phone Lookup, Domain Contacts, Password Exposure, Metadata Exposure y Public Files.
- Pwned Passwords se consulta con k-anonimato y no requiere API key.
- Hydra CLI para simulaciones de fuerza bruta en laboratorio.
- John the Ripper y Hashcat para auditoria offline de hashes.
- hashID para identificacion de formatos probables.
- Crunch y CeWL para generacion controlada de wordlists.

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
    osint/         Busqueda publica de perfiles, usernames, emails y dominios
    passwords/    John, Hashcat, hashID, Crunch, CeWL y wordlists
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
| `CALIGO_JWT_EXPIRATION_MINUTES` | `480` | Duracion del token en minutos. 480 equivale a 8 horas. |
| `CALIGO_BOOTSTRAP_ADMIN_USER` | `admin` | Admin inicial si no hay usuarios. |
| `CALIGO_BOOTSTRAP_ADMIN_EMAIL` | `admin@caligo.local` | Email admin inicial. |
| `CALIGO_BOOTSTRAP_ADMIN_PASSWORD` | `change-me-now` | Password admin local. |
| `CALIGO_SERVER_PORT` | `8080` | Puerto HTTP. |
| `CALIGO_CORS_ALLOWED_ORIGINS` | `http://localhost:*,http://127.0.0.1:*,http://192.168.0.17:*` | Patrones CORS permitidos para el front local/LAN de Vite. |
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
| `CALIGO_VULNERABILITIES_ALLOW_EXTERNAL_TARGETS` | `false` | Si `false`, Nuclei/Nikto/sqlmap solo aceptan URLs privadas/locales. |
| `CALIGO_VULNERABILITIES_MAX_OUTPUT_BYTES` | `1048576` | Limite de salida capturada por herramientas de vulnerabilidades. |
| `CALIGO_VULNERABILITIES_TIMEOUT_SECONDS` | `1800` | Timeout maximo por job Nuclei, Nikto o sqlmap. |
| `CALIGO_NUCLEI_BINARY` | `nuclei` | Binario Nuclei. |
| `CALIGO_SEARCHSPLOIT_BINARY` | `searchsploit` | Binario Searchsploit. |
| `CALIGO_NIKTO_BINARY` | `nikto` | Binario Nikto. |
| `CALIGO_SQLMAP_BINARY` | `sqlmap` | Binario sqlmap. |
| `CALIGO_OSINT_MAX_OUTPUT_BYTES` | `1048576` | Limite de salida capturada por herramientas OSINT. |
| `CALIGO_OSINT_TIMEOUT_SECONDS` | `600` | Timeout maximo por job OSINT. |
| `CALIGO_SHERLOCK_BINARY` | `sherlock` | Binario Sherlock. |
| `CALIGO_MAIGRET_BINARY` | `maigret` | Binario Maigret. |
| `CALIGO_SOCIAL_ANALYZER_BINARY` | `social-analyzer` | Binario Social Analyzer. |
| `CALIGO_HOLEHE_BINARY` | `holehe` | Binario Holehe. |
| `CALIGO_GIT_DUMPER_BINARY` | `git-dumper` | Binario git-dumper. |
| `CALIGO_GIT_DUMPER_OUTPUT_DIR` | `/tmp/caligo/git-dumper` | Directorio controlado para artefactos recuperados por git-dumper. |
| `CALIGO_THEHARVESTER_BINARY` | `theHarvester` | Binario theHarvester. |
| `CALIGO_SPIDERFOOT_BINARY` | `spiderfoot` | Wrapper o binario SpiderFoot usado por los jobs OSINT. |
| `CALIGO_TRUFFLEHOG_BINARY` | `trufflehog` | Binario TruffleHog v3. |
| `CALIGO_TRUFFLEHOG_ALLOWED_ROOTS` | `/tmp/caligo/git-dumper,/var/www/caligo,/opt/caligo` | Raices locales permitidas para escaneos `filesystem` o `file://`. |
| `CALIGO_OSINT_TEMP_DIR` | `/tmp/caligo/osint` | Directorio temporal para filtros include/exclude de TruffleHog. |
| `CALIGO_PASSWORDS_ALLOW_EXTERNAL_TARGETS` | `false` | Si `false`, CeWL solo acepta URLs privadas/locales. |
| `CALIGO_PASSWORDS_MAX_OUTPUT_BYTES` | `1048576` | Limite de salida capturada por John, Hashcat, Crunch y CeWL. |
| `CALIGO_PASSWORDS_TIMEOUT_SECONDS` | `1800` | Timeout maximo por job de contrasenas. |
| `CALIGO_PASSWORDS_WORDLIST_ROOTS` | `/opt/caligo/wordlists,/usr/share/wordlists` | Raices permitidas para wordlists de John/Hashcat. |
| `CALIGO_PASSWORDS_GENERATED_WORDLIST_ROOT` | `/opt/caligo/wordlists/generated` | Directorio de salida para Crunch y CeWL. |
| `CALIGO_JOHN_BINARY` | `john` | Binario John the Ripper. |
| `CALIGO_HASHCAT_BINARY` | `hashcat` | Binario Hashcat. |
| `CALIGO_HASHID_BINARY` | `hashid` | Binario hashID. |
| `CALIGO_CRUNCH_BINARY` | `crunch` | Binario Crunch. |
| `CALIGO_CEWL_BINARY` | `cewl` | Binario CeWL. |
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

Modulos iniciales: `urls`, `nmap`, `openvas`, `metasploit`, `bruteforce`, `nuclei`, `searchsploit`, `nikto`, `sqlmap`, `osint-profile-search`, `sherlock`, `maigret`, `social-analyzer`, `holehe`, `theharvester`, `git-dumper`, `spiderfoot`, `trufflehog`, `passwords`, `encoding`, `steganography`.

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
| `tool` | `varchar(40)` | `nmap`, `openvas`, `metasploit`, `hydra`, `nuclei`, `nikto`, `sqlmap`, `sherlock`, `maigret`, `social-analyzer`, `holehe`, `theharvester`, `git-dumper`, `spiderfoot`, `trufflehog`, `john`, `hashcat`, `crunch` o `cewl`. |
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
| `GET` | `/api/network/identity` | Si | Snapshot de IP cliente observada, IP publica del servidor, interfaces locales y estado VPN. |
| `GET` | `/api/network/vpn/status` | Si | Estado del helper VPN, tuneles activos y salida tecnica. |
| `GET` | `/api/network/vpn/profiles` | Si | Perfiles WireGuard/OpenVPN detectados y metadatos de proveedor/pais/ciudad. |
| `POST` | `/api/network/vpn/connect` | Si, ADMIN | Conecta un perfil VPN allowlisted mediante helper sudo limitado. |
| `POST` | `/api/network/vpn/disconnect` | Si, ADMIN | Desconecta un perfil VPN concreto o todos los tuneles Caligo. |
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
| `GET` | `/api/vulnerabilities/capabilities` | Si | Estado de Nuclei, Searchsploit, Nikto y sqlmap, politica de alcance y opciones permitidas. |
| `POST` | `/api/vulnerabilities/nuclei/runs` | Si | Crea job Nuclei con templates y severidades controladas. |
| `POST` | `/api/vulnerabilities/nikto/runs` | Si | Crea job Nikto sobre una URL privada/local autorizada. |
| `POST` | `/api/vulnerabilities/sqlmap/runs` | Si | Crea job sqlmap con parametros acotados y secretos redactados. |
| `GET` | `/api/vulnerabilities/{tool}/runs` | Si | Ultimos jobs de `nuclei`, `nikto` o `sqlmap`. |
| `GET` | `/api/vulnerabilities/{tool}/runs/{id}` | Si | Estado, progreso, logs y hallazgos normalizados. |
| `GET/POST` | `/api/vulnerabilities/searchsploit/search` | Si | Consulta local Exploit-DB por texto o CVE sin tocar el objetivo. |
| `GET` | `/api/osint/capabilities` | Si | Estado de Caligo People, Sherlock, Maigret, Social Analyzer, Holehe, theHarvester, git-dumper, SpiderFoot y TruffleHog. |
| `POST` | `/api/osint/profile-search/search` | Si | Busca candidatos publicos por nombre real en LinkedIn y redes indexadas. |
| `POST` | `/api/osint/sherlock/runs` | Si | Crea job Sherlock por username. |
| `POST` | `/api/osint/maigret/runs` | Si | Crea job Maigret por username. |
| `POST` | `/api/osint/social-analyzer/runs` | Si | Crea job Social Analyzer por nombre, alias o username. |
| `POST` | `/api/osint/holehe/runs` | Si | Crea job Holehe por email. |
| `POST` | `/api/osint/theharvester/runs` | Si | Crea job theHarvester por dominio. |
| `POST` | `/api/osint/git-dumper/runs` | Si | Crea job git-dumper contra un `.git` expuesto en alcance autorizado. |
| `POST` | `/api/osint/spiderfoot/runs` | Si | Crea job SpiderFoot con target, perfil, modulos y eventos acotados. |
| `POST` | `/api/osint/trufflehog/runs` | Si | Crea job TruffleHog contra Git, GitHub o rutas locales permitidas. |
| `GET` | `/api/osint/{tool}/runs` | Si | Ultimos jobs OSINT del usuario. |
| `GET` | `/api/osint/{tool}/runs/{id}` | Si | Estado, progreso, logs y resultados normalizados. |
| `GET` | `/api/osint/exposure/capabilities` | Si | Capacidades de utilidades OSINT server-side de exposicion autorizada. |
| `POST` | `/api/osint/exposure/email` | Si | Valida email/dominio, MX y patrones profesionales sin tocar buzones. |
| `POST` | `/api/osint/exposure/phone` | Si | Normaliza y clasifica un telefono aportado por el usuario. |
| `POST` | `/api/osint/exposure/domain-contacts` | Si | Extrae contactos publicados en paginas habituales del dominio autorizado. |
| `POST` | `/api/osint/exposure/password` | Si | Consulta Pwned Passwords con k-anonimato SHA-1 prefix. |
| `POST` | `/api/osint/exposure/metadata` | Si | Inspecciona cabeceras y metadatos visibles de una URL publica autorizada. |
| `POST` | `/api/osint/exposure/public-files` | Si | Comprueba ficheros publicos tipicos del dominio: robots, sitemap, security.txt y well-known. |
| `GET` | `/api/passwords/capabilities` | Si | Estado de John, Hashcat, hashID, Crunch, CeWL, modos y wordlists. |
| `GET` | `/api/passwords/wordlists` | Si | Inventario de wordlists bajo raices permitidas. |
| `POST` | `/api/passwords/identify` | Si | Identificacion de formato probable de hash con hashID y heuristicas. |
| `POST` | `/api/passwords/{tool}/runs` | Si | Crea job de John o Hashcat. |
| `GET` | `/api/passwords/{tool}/runs` | Si | Ultimos jobs de la herramienta para el usuario. |
| `GET` | `/api/passwords/{tool}/runs/{id}` | Si | Estado, progreso, logs y resultado de John, Hashcat, Crunch o CeWL. |
| `POST` | `/api/passwords/{tool}/generate` | Si | Genera wordlists con Crunch o CeWL. |
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

## OSINT y exposicion autorizada

Las herramientas OSINT se dividen en jobs persistentes y consultas server-side
rapidas:

- Jobs persistentes: `Sherlock`, `Maigret`, `Social Analyzer`, `Holehe`,
  `theHarvester`, `git-dumper`, `SpiderFoot` y `TruffleHog`, guardados en
  `tool_execution_jobs`.
- Consultas server-side: `Email Exposure`, `Phone Lookup`, `Domain Contacts`,
  `Password Exposure`, `Metadata Exposure` y `Public Files`.

Todas las consultas de exposicion requieren JWT y el campo `authorized=true`.
La intencion es validar exposicion propia, corporativa o expresamente consentida.
No hay endpoints para descubrir domicilios privados ni para atribuir datos
sensibles de terceros.

`git-dumper` requiere `authorized=true`, normaliza URLs HTTP/HTTPS, puede anadir
`/.git/` si la vista lo solicita y escribe siempre en
`CALIGO_GIT_DUMPER_OUTPUT_DIR`; el usuario no puede escoger rutas arbitrarias.
La respuesta del job resume `outputDir`, recuento de ficheros, tamano total,
metadatos `.git` detectados y muestra de logs/stdout/stderr.

`SpiderFoot` requiere `authorized=true` y acepta `target`, `targetType`,
`scanProfile`, `modules`, `eventTypes`, `strictMode` y `timeoutSeconds`. El
backend solo permite nombres de modulo/evento seguros, aplica presets cuando no
se seleccionan modulos explicitos y devuelve hallazgos normalizados por tipo,
modulo, valor, URL y score.

`TruffleHog` requiere `authorized=true` y acepta `sourceType` (`git`, `github`
o `filesystem`), `target`, `results`, `branch`, `maxDepth`, `concurrency`,
`includePaths`, `excludePaths`, `noVerification`, `filterEntropy`,
`scanEntireChunk` y `timeoutSeconds`. Los targets locales solo pueden estar
dentro de `CALIGO_TRUFFLEHOG_ALLOWED_ROOTS`, y los secretos devueltos se
redactan antes de guardarse.

Ejemplo `Email Exposure`:

```json
{
  "email": "persona@empresa.com",
  "fullName": "Persona Autorizada",
  "domain": "empresa.com",
  "generateCandidates": true,
  "authorized": true
}
```

Ejemplo `Domain Contacts`:

```json
{
  "domain": "empresa.com",
  "paths": ["/.well-known/security.txt", "/contacto", "/legal"],
  "timeoutSeconds": 12,
  "authorized": true
}
```

`Password Exposure` usa la API range de Pwned Passwords: Caligo calcula SHA-1 en
el backend y solo envia el prefijo de 5 caracteres al proveedor. El valor de la
password no se guarda en tablas ni en logs de auditoria; se audita unicamente el
prefijo.

La consulta de brechas por email dependiente de API key de pago queda fuera del
producto. Para exposicion de cuentas se priorizan fuentes locales, Holehe,
theHarvester y validaciones de dominio sin depender de proveedores cerrados.

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
/opt/caligo/wordlists/users/users-basic.txt
/opt/caligo/wordlists/passwords/passwords-basic.txt
/opt/caligo/wordlists/combos/combos-basic.txt
```

### Contrasenas

El modulo de contrasenas es offline y orientado a auditoria autorizada. No
intenta autenticarse contra servicios remotos; para eso existe Hydra dentro de
Fuerza Bruta. Los jobs quedan guardados en `tool_execution_jobs` para que el
frontend pueda reenganchar el progreso aunque el usuario cambie de vista.

`GET /api/passwords/capabilities` devuelve:

- Estado y version de `john`, `hashcat`, `hashid`, `crunch` y `cewl`.
- Formatos John permitidos.
- Modos Hashcat permitidos.
- Wordlists visibles bajo las raices permitidas.
- Defaults de laboratorio para pruebas locales.

`POST /api/passwords/identify` acepta:

```json
{
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99"
}
```

`POST /api/passwords/john/runs` acepta:

```json
{
  "hashes": "5f4dcc3b5aa765d61d8327deb882cf99",
  "hashFormat": "raw-md5",
  "wordlistText": "password\npassword123\npepito53"
}
```

`POST /api/passwords/hashcat/runs` acepta diccionario o mascara:

```json
{
  "hashes": "5f4dcc3b5aa765d61d8327deb882cf99",
  "hashcatMode": "0",
  "attackMode": "wordlist",
  "wordlistFile": "/opt/caligo/wordlists/passwords/passwords-basic.txt"
}
```

```json
{
  "hashes": "5f4dcc3b5aa765d61d8327deb882cf99",
  "hashcatMode": "0",
  "attackMode": "mask",
  "mask": "?l?l?l?l?d?d"
}
```

`POST /api/passwords/crunch/generate` crea ficheros bajo
`CALIGO_PASSWORDS_GENERATED_WORDLIST_ROOT` y limita el espacio estimado a
500000 lineas:

```json
{
  "minLength": 4,
  "maxLength": 5,
  "charset": "abcdefghijklmnopqrstuvwxyz0123456789",
  "outputName": "crunch-lab.txt"
}
```

`POST /api/passwords/cewl/generate` genera wordlists desde URLs autorizadas. Por
defecto bloquea objetivos publicos si `CALIGO_PASSWORDS_ALLOW_EXTERNAL_TARGETS`
esta a `false`:

```json
{
  "url": "http://192.168.0.10",
  "depth": 2,
  "minWordLength": 4,
  "withNumbers": true,
  "outputName": "cewl-lab.txt"
}
```

Wordlists instaladas y permitidas en el servidor 2:

```text
/opt/caligo/wordlists/passwords/passwords-basic.txt
/opt/caligo/wordlists/users/users-basic.txt
/opt/caligo/wordlists/combos/combos-basic.txt
/opt/caligo/wordlists/patterns/masks-basic.txt
/opt/caligo/wordlists/seclists/Usernames
/opt/caligo/wordlists/seclists/Passwords/Common-Credentials
/opt/caligo/wordlists/seclists/Discovery/Web-Content
/opt/caligo/wordlists/generated
```

Los hashes y diccionarios pegados se escriben en directorios temporales y se
eliminan al terminar. Las rutas de wordlist enviadas por el cliente solo se
aceptan si pertenecen a `CALIGO_PASSWORDS_WORDLIST_ROOTS` o al directorio de
generados.

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
- `katana`
- `gau`
- `subfinder`
- `amass`
- `ffuf`

Herramientas instaladas en el servidor 2 durante el primer despliegue: `nmap`, `ffuf`, `john`, `hashcat`, `hashid`, `crunch`, `cewl`, `exiftool`, `steghide`, `binwalk`, `zsteg`, `httpx`, `katana`, `gau`, `subfinder` y `amass`.

Herramientas instaladas para reconocimiento activo: `nmap`, `gvm`, `gvmd`, `openvas-scanner`, `ospd-openvas` y `gvm-tools`. Las herramientas activas deben ejecutarse siempre con alcance autorizado, trazabilidad, limites y registro de usuario.

Herramientas instaladas para validacion controlada: `metasploit-framework` con
`msgrpc` gestionado por systemd y expuesto solo en localhost. El modulo de
vulnerabilidades tambien usa `nuclei`, `searchsploit`, `nikto` y `sqlmap`.
Nuclei se instala en `/usr/local/bin` y sus templates se actualizan con
`nuclei -update-templates`; Searchsploit se alimenta del clone local
`/opt/exploitdb`.

Herramientas instaladas para fuerza bruta controlada: `hydra`. Las wordlists de
laboratorio de Caligo viven en `/opt/caligo/wordlists` y las wordlists del
sistema se leen solo si estan bajo las raices permitidas por
`CALIGO_HYDRA_WORDLIST_ROOTS`.

Herramientas instaladas para contrasenas: `john`, `john-data`, `hashcat`,
`hashid`, `crunch` y `cewl`. El set de wordlists de laboratorio vive bajo
`/opt/caligo/wordlists` y el subset de SecLists descargado queda separado en
`/opt/caligo/wordlists/seclists`.

### Redes, identidad y VPN

El backend expone `GET /api/network/identity` para que el frontend pueda mostrar
en todo momento la identidad de red:

- IP observada del cliente desde `X-Forwarded-For`, `X-Real-IP` o `remoteAddr`.
- IP publica de salida del servidor, cacheada durante unos segundos y consultada
  en proveedores externos (`api.ipify.org`, `icanhazip.com`, `ifconfig.me`).
- Hostname e interfaces locales no loopback del servidor.
- Estado VPN calculado por el helper de control.

Los perfiles VPN se cargan desde rutas allowlisted, sin aceptar rutas recibidas
desde el navegador:

```text
/etc/caligo/vpn/wireguard/*.conf
/etc/caligo/vpn/openvpn/*.ovpn
/etc/caligo/vpn/metadata/*.json
```

Metadatos opcionales por perfil, con el mismo nombre base:

```json
{
  "provider": "Mullvad",
  "country": "ES",
  "city": "Madrid",
  "label": "Mullvad ES Madrid",
  "description": "Salida WireGuard de laboratorio"
}
```

Proveedores recomendados para cargar perfiles privados: Mullvad, Proton VPN e
IVPN. Caligo no guarda credenciales de estos proveedores: se deben generar los
perfiles en la cuenta del proveedor y copiarlos al servidor. Para WireGuard se
recomienda preferir `.conf`; para OpenVPN, `.ovpn` con auth file root-only si el
proveedor lo requiere.

El control se ejecuta con helper root-owned:

```bash
sudo install -o root -g root -m 0755 ops/caligo-vpn-control.sh /usr/local/sbin/caligo-vpn-control
sudo install -d -o root -g root -m 0700 /etc/caligo/vpn/wireguard /etc/caligo/vpn/openvpn /etc/caligo/vpn/metadata
```

Permiso sudo minimo:

```sudoers
fran ALL=(root) NOPASSWD: /usr/local/sbin/caligo-vpn-control *
```

Herramientas base para el servidor:

```bash
sudo apt-get update
sudo apt-get install -y wireguard-tools openvpn resolvconf
```

### Actualizaciones desde Caligo

El endpoint `GET /api/system/tools` devuelve el inventario del servidor con
version actual, binario detectado, grupo funcional y gestor (`apt`, `go`, `git`,
`gem` o `python`). El frontend lo usa en `Ajustes > Actualizaciones`.

El endpoint `POST /api/system/tools/{id}/update` solo acepta IDs definidos en el
backend. No recibe comandos desde el navegador y requiere rol `ADMIN`. Cada
accion se audita como `SYSTEM_TOOL_UPDATE_START`, `SYSTEM_TOOL_UPDATE_SUCCESS`
o `SYSTEM_TOOL_UPDATE_FAILED`.

Los updates no ejecutan comandos recibidos desde el navegador. El backend llama
siempre a un helper root-owned con allowlist:

```bash
sudo -n /usr/local/sbin/caligo-tool-update <tool-id>
```

El script de referencia vive en `ops/caligo-tool-update.sh` y se instala como
`/usr/local/sbin/caligo-tool-update`, propietario `root:root` y modo `0755`.
Dentro del script:

- Paquetes APT: `apt-get update` y `apt-get install --only-upgrade -y <paquete>`.
- Herramientas Go: `go install <modulo>@latest` en un `GOBIN` temporal e `install` a `/usr/local/bin`.
- Repositorios Git gestionados: `git -C <repo> pull --ff-only`.
- Gems: `gem update <gem>`.
- Herramientas Python OSINT: `pipx install --force <paquete>` bajo `/opt/caligo-pipx` con wrapper estable en `/usr/local/bin`.
- `theHarvester`: clon oficial en `/opt/theHarvester`, `uv sync` y wrapper `/usr/local/bin/theHarvester`.

Para que funcione desde el servicio sin hardcodear passwords, el servidor debe
conceder `NOPASSWD` solo al helper:

```sudoers
fran ALL=(root) NOPASSWD: /usr/local/sbin/caligo-tool-update *
```

El helper valida el `tool-id` con un `case` cerrado; si no existe ese permiso o
la herramienta no esta allowlisted, el endpoint devuelve el fallo en la salida
de la operacion y no queda bloqueado.

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
CALIGO_VULNERABILITIES_ALLOW_EXTERNAL_TARGETS=false
CALIGO_NUCLEI_BINARY=nuclei
CALIGO_SEARCHSPLOIT_BINARY=searchsploit
CALIGO_NIKTO_BINARY=nikto
CALIGO_SQLMAP_BINARY=sqlmap
CALIGO_JOHN_BINARY=john
CALIGO_HASHCAT_BINARY=hashcat
CALIGO_HASHID_BINARY=hashid
CALIGO_CRUNCH_BINARY=crunch
CALIGO_CEWL_BINARY=cewl
CALIGO_PASSWORDS_WORDLIST_ROOTS=/opt/caligo/wordlists,/usr/share/wordlists
CALIGO_PASSWORDS_GENERATED_WORDLIST_ROOT=/opt/caligo/wordlists/generated
CALIGO_PASSWORDS_ALLOW_EXTERNAL_TARGETS=false
CALIGO_SYSTEM_TOOL_UPDATE_TIMEOUT_SECONDS=900
CALIGO_VPN_WIREGUARD_DIR=/etc/caligo/vpn/wireguard
CALIGO_VPN_OPENVPN_DIR=/etc/caligo/vpn/openvpn
CALIGO_VPN_METADATA_DIR=/etc/caligo/vpn/metadata
CALIGO_VPN_HELPER=/usr/local/sbin/caligo-vpn-control
CALIGO_VPN_COMMAND_TIMEOUT_SECONDS=45
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
