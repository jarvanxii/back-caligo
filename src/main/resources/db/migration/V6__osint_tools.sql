insert into tool_modules (id, code, display_name, description, enabled, created_at)
values
    ('10000000-0000-0000-0000-000000000020', 'osint-profile-search', 'Caligo People', 'Busqueda publica de perfiles sociales por nombre y pistas de identidad.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000021', 'sherlock', 'Sherlock', 'Enumeracion de usernames en redes sociales y plataformas publicas.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000022', 'maigret', 'Maigret', 'Correlacion OSINT de usernames con scoring y busqueda multi-sitio.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000023', 'social-analyzer', 'Social Analyzer', 'Correlacion de nombres y aliases contra perfiles de redes sociales.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000024', 'holehe', 'Holehe', 'Comprobacion de uso publico de emails en servicios online.', true, current_timestamp(6)),
    ('10000000-0000-0000-0000-000000000025', 'theharvester', 'theHarvester', 'Recoleccion OSINT de emails, hosts y fuentes publicas por dominio.', true, current_timestamp(6))
on duplicate key update
    display_name = values(display_name),
    description = values(description),
    enabled = values(enabled);
