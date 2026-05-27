insert into tool_modules (id, code, display_name, description, enabled, created_at) values
    ('10000000-0000-0000-0000-000000000008', 'nmap', 'Nmap', 'Reconocimiento de red, descubrimiento de hosts y escaneo de puertos en entornos autorizados.', true, current_timestamp(6))
on duplicate key update
    display_name = values(display_name),
    description = values(description),
    enabled = values(enabled);
