create table users (
    id uuid primary key,
    username varchar(80) not null,
    email varchar(160) not null,
    password_hash varchar(255) not null,
    role varchar(30) not null,
    active boolean not null default true,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    constraint users_role_chk check (role in ('ADMIN', 'OPERATOR', 'VIEWER'))
);

create unique index users_username_lower_uk on users (lower(username));
create unique index users_email_lower_uk on users (lower(email));
create index users_role_idx on users (role);

create table tool_modules (
    id uuid primary key,
    code varchar(60) not null,
    display_name varchar(120) not null,
    description varchar(500) not null,
    enabled boolean not null default true,
    created_at timestamptz not null default now()
);

create unique index tool_modules_code_uk on tool_modules (code);
create index tool_modules_enabled_idx on tool_modules (enabled);

create table audit_events (
    id uuid primary key,
    username varchar(80),
    action varchar(120) not null,
    target varchar(240),
    ip_address varchar(80),
    created_at timestamptz not null default now()
);

create index audit_events_created_at_idx on audit_events (created_at desc);
create index audit_events_username_idx on audit_events (username);

insert into tool_modules (id, code, display_name, description, enabled, created_at) values
    ('10000000-0000-0000-0000-000000000001', 'openvas', 'OpenVAS', 'Escaneo de vulnerabilidades en entornos autorizados.', true, now()),
    ('10000000-0000-0000-0000-000000000002', 'metasploit', 'Metasploit', 'Gestión de pruebas de explotación controlada.', true, now()),
    ('10000000-0000-0000-0000-000000000003', 'urls', 'URLs', 'Análisis, clasificación y utilidades sobre URLs.', true, now()),
    ('10000000-0000-0000-0000-000000000004', 'passwords', 'Contraseñas', 'Laboratorio de hashes, diccionarios y fuerza bruta controlada.', true, now()),
    ('10000000-0000-0000-0000-000000000005', 'steganography', 'Esteganografía', 'Laboratorio de ocultación, extracción y análisis de información.', true, now());
