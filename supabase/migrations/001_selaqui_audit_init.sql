-- Selaqui security audit app. Isolated schema in the client-portal project; not exposed through the API.
-- Replace the three <...> placeholders before running. Real values are never committed.
create schema if not exists selaqui;
revoke all on schema selaqui from public, anon, authenticated;

create table selaqui.users(
  username text primary key,
  display_name text not null,
  pass_hash text not null,
  created_at timestamptz not null default now()
);
create table selaqui.sessions(
  token_hash text primary key,
  username text not null references selaqui.users(username),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '30 days'
);
create table selaqui.login_failures(
  id bigserial primary key,
  username text not null,
  at timestamptz not null default now()
);
-- Append-only log. Entries are never edited; a mistake is retracted by a later entry.
create table selaqui.entries(
  id text primary key,
  seq bigserial unique,
  author text not null references selaqui.users(username),
  kind text not null,
  scope text,
  item_id text,
  status text,
  sev text,
  evid text[] not null default '{}',
  ref text,
  provided_by text,
  body text,
  photos jsonb not null default '[]',
  geo jsonb,
  gerr text,
  target text,
  device_ts timestamptz not null,
  server_ts timestamptz not null default now()
);
create index on selaqui.entries(scope, item_id);
create table selaqui.backups(
  id bigserial primary key,
  created_at timestamptz not null default now(),
  path text not null,
  entries int not null,
  bytes int not null,
  trigger text not null
);
create table selaqui.config(key text primary key, value text not null);

alter table selaqui.users enable row level security;
alter table selaqui.sessions enable row level security;
alter table selaqui.login_failures enable row level security;
alter table selaqui.entries enable row level security;
alter table selaqui.backups enable row level security;
alter table selaqui.config enable row level security;
revoke all on all tables in schema selaqui from public, anon, authenticated;

insert into selaqui.users(username, display_name, pass_hash) values
 ('ajay','Ajay Kumar', extensions.crypt('<AJAY_PASSWORD>', extensions.gen_salt('bf', 10))),
 ('anis','Anis Rao',   extensions.crypt('<ANIS_PASSWORD>', extensions.gen_salt('bf', 10)));
insert into selaqui.config values ('cron_secret','<RANDOM_CRON_SECRET>');

insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('selaqui-audit','selaqui-audit', false, 6291456, array['image/jpeg','image/png','image/webp','application/json'])
on conflict (id) do nothing;
