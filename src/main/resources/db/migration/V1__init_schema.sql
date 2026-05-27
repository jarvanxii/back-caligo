create table users (
    id char(36) primary key,
    username varchar(80) not null,
    email varchar(160) not null,
    password_hash varchar(255) not null,
    role varchar(30) not null,
    active boolean not null default true,
    created_at datetime(6) not null default current_timestamp(6),
    updated_at datetime(6) not null default current_timestamp(6),
    constraint users_role_chk check (role in ('ADMIN', 'OPERATOR', 'VIEWER'))
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci;

create unique index users_username_uk on users (username);
create unique index users_email_uk on users (email);
create index users_role_idx on users (role);

create table tool_modules (
    id char(36) primary key,
    code varchar(60) not null,
    display_name varchar(120) not null,
    description varchar(500) not null,
    enabled boolean not null default true,
    created_at datetime(6) not null default current_timestamp(6)
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci;

create unique index tool_modules_code_uk on tool_modules (code);
create index tool_modules_enabled_idx on tool_modules (enabled);

create table audit_events (
    id char(36) primary key,
    username varchar(80),
    action varchar(120) not null,
    target varchar(240),
    ip_address varchar(80),
    created_at datetime(6) not null default current_timestamp(6)
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci;

create index audit_events_created_at_idx on audit_events (created_at desc);
create index audit_events_username_idx on audit_events (username);

insert into tool_modules (id, code, display_name, description, enabled, created_at) values
    ('10000000-0000-0000-0000-000000000001', 'openvas', 'OpenVAS', 'Escaneo de vulnerabilidades en entornos autorizados.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000002', 'metasploit', 'Metasploit', 'Gestion de pruebas de explotacion controlada.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000003', 'urls', 'URLs', 'Analisis, clasificacion y utilidades sobre URLs.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000004', 'passwords', 'Contrasenas', 'Laboratorio de hashes, diccionarios y fuerza bruta controlada.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000005', 'steganography', 'Esteganografia', 'Laboratorio de ocultacion, extraccion y analisis de informacion.', true, current_timestamp(6));
