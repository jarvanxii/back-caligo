# Caligo Backend

Backend base de Caligo, preparado para exponer una API web con autenticacion JWT y una base de datos local versionada con Flyway.

La idea de este primer esqueleto es dejar una plataforma limpia sobre la que ir montando los laboratorios y conectores de herramientas: OpenVAS, Metasploit, utilidades de URLs, contrasenas, esteganografia y los modulos que vengan despues.

## Stack elegido

- Java 21.
- Spring Boot 3.3.5.
- Maven 3.9.x.
- Spring Web para API REST.
- Spring Security para autenticacion y autorizacion.
- JJWT 0.12.6 para emitir y validar tokens JWT.
- Spring Data JPA + Hibernate para persistencia.
- PostgreSQL 16 como base de datos local.
- Flyway para migraciones SQL versionadas.
- Spring Validation para validar DTOs de entrada.
- Spring Actuator para health checks basicos.
- Docker Compose para levantar PostgreSQL en local.

## Estructura del proyecto

```text
back-caligo/
  compose.yml
  pom.xml
  src/main/java/com/caligo/backend/
    auth/          Login, registro y DTOs de autenticacion
    audit/         Entidad base para auditoria
    common/        Manejo comun de errores REST
    config/        Seguridad, filtro JWT y bootstrap de admin
    health/        Endpoints de salud publicos y privados
    module/        Modulos funcionales visibles desde el frontend
    security/      Servicio JWT y carga de usuarios para Spring Security
    user/          Usuario, roles, repositorio y endpoint /api/me
  src/main/resources/
    application.yml
    db/migration/
      V1__init_schema.sql
```

## Base de datos local

La base local se levanta con PostgreSQL mediante `compose.yml`.

```powershell
docker compose up -d
```

Conexion por defecto:

```text
Host: localhost
Puerto: 5432
Base de datos: caligo
Usuario: caligo
Password: caligo_dev
```

Spring ejecuta Flyway al arrancar. La migracion inicial esta en:

```text
src/main/resources/db/migration/V1__init_schema.sql
```

### Tabla `users`

Usuarios de la plataforma.

| Columna | Tipo | Descripcion |
| --- | --- | --- |
| `id` | `uuid` | Identificador primario. |
| `username` | `varchar(80)` | Nombre de usuario. Unico ignorando mayusculas. |
| `email` | `varchar(160)` | Email. Unico ignorando mayusculas. |
| `password_hash` | `varchar(255)` | Password cifrada con BCrypt. |
| `role` | `varchar(30)` | `ADMIN`, `OPERATOR` o `VIEWER`. |
| `active` | `boolean` | Permite bloquear usuarios sin borrarlos. |
| `created_at` | `timestamptz` | Fecha de creacion. |
| `updated_at` | `timestamptz` | Fecha de ultima actualizacion. |

Indices:

- `users_username_lower_uk`: evita duplicados por nombre ignorando mayusculas.
- `users_email_lower_uk`: evita duplicados por email ignorando mayusculas.
- `users_role_idx`: consultas por rol.

### Tabla `tool_modules`

Catalogo de modulos que vera el frontend.

| Columna | Tipo | Descripcion |
| --- | --- | --- |
| `id` | `uuid` | Identificador primario. |
| `code` | `varchar(60)` | Codigo interno estable. |
| `display_name` | `varchar(120)` | Nombre visible. |
| `description` | `varchar(500)` | Descripcion corta. |
| `enabled` | `boolean` | Activa o desactiva el modulo. |
| `created_at` | `timestamptz` | Fecha de creacion. |

Modulos iniciales:

- `openvas`
- `metasploit`
- `urls`
- `passwords` (`Contraseñas`)
- `steganography` (`Esteganografía`)

### Tabla `audit_events`

Base para registrar acciones sensibles.

| Columna | Tipo | Descripcion |
| --- | --- | --- |
| `id` | `uuid` | Identificador primario. |
| `username` | `varchar(80)` | Usuario que ejecuta la accion. |
| `action` | `varchar(120)` | Accion realizada. |
| `target` | `varchar(240)` | Recurso afectado. |
| `ip_address` | `varchar(80)` | IP de origen. |
| `created_at` | `timestamptz` | Fecha del evento. |

Esta tabla queda preparada desde el principio porque una plataforma de ciberseguridad necesita trazabilidad antes de empezar a lanzar herramientas.

## Variables de entorno

Hay un ejemplo en `.env.example`.

| Variable | Valor local por defecto | Uso |
| --- | --- | --- |
| `CALIGO_DB_URL` | `jdbc:postgresql://localhost:5432/caligo` | JDBC de PostgreSQL. |
| `CALIGO_DB_USER` | `caligo` | Usuario de BBDD. |
| `CALIGO_DB_PASSWORD` | `caligo_dev` | Password de BBDD. |
| `CALIGO_JWT_SECRET` | secreto local largo | Clave HMAC para firmar JWT. Debe tener minimo 32 bytes. |
| `CALIGO_JWT_EXPIRATION_MINUTES` | `60` | Duracion del token. |
| `CALIGO_BOOTSTRAP_ADMIN_USER` | `admin` | Usuario admin inicial si la tabla `users` esta vacia. |
| `CALIGO_BOOTSTRAP_ADMIN_EMAIL` | `admin@caligo.local` | Email del admin inicial. |
| `CALIGO_BOOTSTRAP_ADMIN_PASSWORD` | `change-me-now` | Password local inicial. Cambiar antes de desplegar. |
| `CALIGO_SERVER_PORT` | `8080` | Puerto HTTP del backend. |

## Ejecutar en local

Este proyecto compila con Java 21. En esta maquina puedes apuntar Maven al JDK 21 asi:

```powershell
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-21.0.11.10-hotspot"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
```

Arranque completo:

```powershell
cd C:\Users\Jarva\Desktop\git-repos\back-caligo
docker compose up -d
mvn spring-boot:run
```

En el primer arranque:

1. Flyway crea las tablas.
2. Se insertan los modulos iniciales.
3. Si no hay usuarios, se crea el admin local.

## Endpoints actuales

| Metodo | Ruta | JWT | Descripcion |
| --- | --- | --- | --- |
| `GET` | `/api/health` | No | Health check publico. |
| `GET` | `/actuator/health` | No | Health check de Spring Actuator. |
| `POST` | `/api/auth/login` | No | Login con usuario y password. |
| `POST` | `/api/auth/register` | No | Registro temporal para desarrollo. Crea usuarios `VIEWER`. |
| `GET` | `/api/me` | Si | Perfil del usuario autenticado. |
| `GET` | `/api/modules` | Si | Lista de modulos habilitados. |
| `GET` | `/api/modules?enabledOnly=false` | Si | Lista de todos los modulos. |
| `GET` | `/api/health/private` | Si | Prueba rapida de endpoint protegido. |

## Flujo JWT

Login con PowerShell:

```powershell
$body = @{
  username = "admin"
  password = "change-me-now"
} | ConvertTo-Json

$response = Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:8080/api/auth/login" `
  -ContentType "application/json" `
  -Body $body

$token = $response.accessToken
$token
```

Llamada protegida:

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:8080/api/modules" `
  -Headers @{ Authorization = "Bearer $token" }
```

Respuesta esperada de login:

```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "user": {
    "id": "uuid",
    "username": "admin",
    "email": "admin@caligo.local",
    "role": "ADMIN"
  }
}
```

## Seguridad inicial

- La API es stateless: no hay sesion de servidor.
- El token se envia con `Authorization: Bearer <token>`.
- Las passwords se guardan con BCrypt, nunca en claro.
- `CALIGO_JWT_SECRET` debe cambiarse fuera de local.
- El registro publico es temporal para desarrollo; cuando exista panel de administracion conviene cerrarlo o dejarlo solo para `ADMIN`.
- Antes de integrar herramientas ofensivas, cada ejecucion deberia guardar auditoria, usuario, parametros, objetivo, resultado y estado.
- Las herramientas como Metasploit, OpenVAS, Hashcat o John deberian ejecutarse mediante servicios aislados, colas y perfiles de permisos, no como comandos directos desde un controlador HTTP.

## Proximos pasos recomendados

1. Conectar el login del frontend de Caligo contra `/api/auth/login`.
2. Guardar el JWT en el cliente y enviarlo en cada peticion protegida.
3. Crear una capa de permisos por modulo: `OPENVAS_RUN`, `METASPLOIT_RUN`, `HASHCAT_RUN`, etc.
4. Crear tablas de ejecuciones: jobs, targets, resultados, logs y artefactos.
5. Meter auditoria real en login, ejecucion de herramientas y cambios de configuracion.
6. Sustituir el registro publico por gestion de usuarios desde un panel admin.
