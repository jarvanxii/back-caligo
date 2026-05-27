# Repository Guidelines

## Project Structure & Module Organization

This is the Spring Boot backend for Caligo. The main package is
`com.caligo.backend`. Authentication code lives in `auth` and `security`;
Spring configuration is in `config`; users and roles are in `user`; visible
tool modules are in `module`; future traceability starts in `audit`; shared REST
error handling lives in `common`.

Database schema is not generated from Hibernate. Flyway migrations under
`src/main/resources/db/migration` are the source of truth, and JPA runs with
`ddl-auto=validate`.

## Build, Test, and Development Commands

Use Java 21. On this Windows machine Maven may need `JAVA_HOME` pointed at the
JDK 21 installation before running commands.

```powershell
docker compose up -d
mvn spring-boot:run
mvn test
mvn -DskipTests package
```

`docker compose up -d` starts MariaDB 11 for local development. `mvn test`
runs the JUnit test suite. `mvn -DskipTests package` creates the runnable jar in
`target/`.

## Coding Style & Naming Conventions

Use plain Spring Boot conventions: constructor injection, records for request
and response DTOs, package-private Spring beans where possible, and explicit
entities for database tables. Keep controllers thin; put security-specific work
in `security` or `config`. Do not introduce Lombok unless the project adopts it
explicitly.

## Testing Guidelines

There is a minimal JUnit 5 test scaffold. For now, compile and test with Java
21. When adding behavior, prefer focused service/controller tests and keep DB
changes covered by Flyway migrations rather than ad hoc Hibernate updates.

## Agent Instructions

Never commit `.env`, real JWT secrets, database passwords, dumps with private
data or production credentials. Any future integration with offensive security
tools must be audited and scoped to controlled, authorized environments.

## Backend Deployment Workflow

When backend code or backend configuration changes, keep the LAN backend ready
for local frontend testing. The expected flow is:

1. Run the relevant backend verification locally, normally `mvn test` or
   `mvn -DskipTests package` depending on the change.
2. Commit only backend changes in this repository.
3. Push `back-caligo` to `origin`.
4. SSH into the Caligo server, pull the backend repo, rebuild/restart the
   backend service and verify `/api/health`.

Do not deploy the frontend unless the user explicitly asks for it; the frontend
is normally tested locally with Vite.

Current project context has used `192.168.0.253` as the Caligo server. If a task
mentions `192.168.0.254`, confirm the target before deploying because the local
credentials file maps that LAN address to another application server.

## Commit & Pull Request Guidelines

This repo has no commit history yet. Use short Spanish descriptive commits and
keep backend changes separate from `front-caligo`.
