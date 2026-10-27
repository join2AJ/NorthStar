-- Server-side audit trail and tamper evidence.
-- * selaqui.activity records every action (sign-in, failed sign-in, entry, withdrawal, photo upload, backup)
--   with server time, actor, GPS sent by the phone, IP and device.
-- * entries and activity are append-only (update/delete blocked by trigger).
-- * each row carries sha256(previous hash | row content); verify_chains() recomputes both chains.
create table selaqui.activity(
  id bigserial primary key,
  at timestamptz not null default now(),
  actor text,
  action text not null,
  target text,
  detail jsonb,
  geo jsonb,
  ip text,
  ua text,
  prev_hash text,
  hash text
);
alter table selaqui.activity enable row level security;
revoke all on selaqui.activity from public, anon, authenticated;
alter table selaqui.entries add column ip text, add column ua text, add column prev_hash text, add column hash text;

create or replace function selaqui.chain_hash() returns trigger
language plpgsql set search_path = '' set timezone = 'UTC' as $$
declare prev text; keycol text := tg_argv[0];
begin
  perform pg_advisory_xact_lock(hashtext('selaqui.' || tg_table_name));
  execute format('select hash from selaqui.%I where hash is not null order by %I desc limit 1', tg_table_name, keycol) into prev;
  new.prev_hash := coalesce(prev, 'GENESIS');
  new.hash := encode(extensions.digest(new.prev_hash || '|' || (to_jsonb(new) - 'hash' - 'prev_hash')::text, 'sha256'), 'hex');
  return new;
end $$;

create or replace function selaqui.append_only() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'selaqui.% is append-only: rows cannot be changed or deleted', tg_table_name;
end $$;

-- backfill the chain for rows that already exist
do $$
declare r record; prev text := 'GENESIS';
begin
  set local timezone = 'UTC';
  for r in select * from selaqui.entries order by seq loop
    update selaqui.entries set prev_hash = prev,
      hash = encode(extensions.digest(prev || '|' || (to_jsonb(r) - 'hash' - 'prev_hash')::text, 'sha256'), 'hex')
    where id = r.id returning hash into prev;
  end loop;
end $$;

create trigger entries_chain before insert on selaqui.entries for each row execute function selaqui.chain_hash('seq');
create trigger activity_chain before insert on selaqui.activity for each row execute function selaqui.chain_hash('id');
create trigger entries_lock before update or delete on selaqui.entries for each row execute function selaqui.append_only();
create trigger activity_lock before update or delete on selaqui.activity for each row execute function selaqui.append_only();

create or replace function selaqui.verify_chains() returns jsonb
language plpgsql set search_path = '' set timezone = 'UTC' as $$
declare r record; prev text; h text; res jsonb := '{}'; n int; bad text;
begin
  prev := 'GENESIS'; n := 0; bad := null;
  for r in select * from selaqui.entries order by seq loop
    n := n + 1;
    h := encode(extensions.digest(prev || '|' || (to_jsonb(r) - 'hash' - 'prev_hash')::text, 'sha256'), 'hex');
    if r.prev_hash is distinct from prev or r.hash is distinct from h then bad := r.id; exit; end if;
    prev := r.hash;
  end loop;
  res := res || jsonb_build_object('entries', jsonb_build_object('rows', n, 'ok', bad is null, 'firstBad', bad, 'head', prev));
  prev := 'GENESIS'; n := 0; bad := null;
  for r in select * from selaqui.activity order by id loop
    n := n + 1;
    h := encode(extensions.digest(prev || '|' || (to_jsonb(r) - 'hash' - 'prev_hash')::text, 'sha256'), 'hex');
    if r.prev_hash is distinct from prev or r.hash is distinct from h then bad := r.id::text; exit; end if;
    prev := r.hash;
  end loop;
  return res || jsonb_build_object('activity', jsonb_build_object('rows', n, 'ok', bad is null, 'firstBad', bad, 'head', prev));
end $$;
revoke all on function selaqui.verify_chains() from public, anon, authenticated;
