create table url_analysis_jobs (
    id char(36) primary key,
    username varchar(80),
    input_target varchar(1000) not null,
    normalized_url varchar(1200) not null,
    host varchar(255) not null,
    mode varchar(40) not null,
    risk_score integer not null,
    verdict varchar(80) not null,
    private_network_allowed boolean not null default false,
    duration_ms integer not null,
    result_json text not null,
    created_at datetime(6) not null default current_timestamp(6)
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci;

create index url_analysis_jobs_created_at_idx on url_analysis_jobs (created_at desc);
create index url_analysis_jobs_host_idx on url_analysis_jobs (host);
create index url_analysis_jobs_username_idx on url_analysis_jobs (username);

insert into tool_modules (id, code, display_name, description, enabled, created_at) values
    ('10000000-0000-0000-0000-000000000006', 'bruteforce', 'Fuerza Bruta', 'Simulacion y validacion de controles ante fuerza bruta en entornos autorizados.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000007', 'encoding', 'Codificacion', 'Transformaciones de datos, URL encoding, Base64, Hex y formatos auxiliares.', true, current_timestamp(6))
on duplicate key update
    display_name = values(display_name),
    description = values(description),
    enabled = values(enabled);

update tool_modules set
    display_name = 'Contrasenas',
    description = 'Laboratorio de hashes, diccionarios y fuerza bruta controlada.'
where code = 'passwords';

update tool_modules set
    display_name = 'Esteganografia',
    description = 'Laboratorio de ocultacion, extraccion y analisis de informacion.'
where code = 'steganography';

update tool_modules set
    description = 'Gestion de pruebas de explotacion controlada.'
where code = 'metasploit';

update tool_modules set
    description = 'Analisis, clasificacion y utilidades sobre URLs.'
where code = 'urls';
