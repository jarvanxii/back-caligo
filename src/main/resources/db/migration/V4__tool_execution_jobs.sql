create table tool_execution_jobs (
    id char(36) primary key,
    username varchar(80) not null,
    tool varchar(40) not null,
    target varchar(240) not null,
    status varchar(30) not null,
    progress integer not null default 0,
    phase varchar(160),
    parameters_json text not null,
    result_json longtext,
    error_message text,
    command_preview varchar(1200),
    started_at datetime(6),
    completed_at datetime(6),
    created_at datetime(6) not null default current_timestamp(6),
    updated_at datetime(6) not null default current_timestamp(6) on update current_timestamp(6),
    constraint tool_execution_jobs_status_chk check (status in ('QUEUED', 'RUNNING', 'COMPLETED', 'FAILED', 'CANCELLED'))
) engine=InnoDB default charset=utf8mb4 collate=utf8mb4_unicode_ci;

create index tool_execution_jobs_username_created_idx on tool_execution_jobs (username, created_at desc);
create index tool_execution_jobs_tool_created_idx on tool_execution_jobs (tool, created_at desc);
create index tool_execution_jobs_status_idx on tool_execution_jobs (status);
