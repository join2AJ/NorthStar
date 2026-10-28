-- Structured extras on an entry: recommendation, risk likelihood/impact, SOP topics.
alter table selaqui.entries add column extra jsonb;

-- Hash content leaves out `extra` when it is null, so rows written before this column existed keep their hashes.
create or replace function selaqui.chain_hash() returns trigger
language plpgsql set search_path = '' set timezone = 'UTC' as $$
declare prev text; keycol text := tg_argv[0]; body jsonb;
begin
  perform pg_advisory_xact_lock(hashtext('selaqui.' || tg_table_name));
  execute format('select hash from selaqui.%I where hash is not null order by %I desc limit 1', tg_table_name, keycol) into prev;
  new.prev_hash := coalesce(prev, 'GENESIS');
  body := to_jsonb(new) - 'hash' - 'prev_hash';
  if body->'extra' = 'null'::jsonb then body := body - 'extra'; end if;
  new.hash := encode(extensions.digest(new.prev_hash || '|' || body::text, 'sha256'), 'hex');
  return new;
end $$;

create or replace function selaqui.verify_chains() returns jsonb
language plpgsql set search_path = '' set timezone = 'UTC' as $$
declare r record; prev text; h text; res jsonb := '{}'; n int; bad text; body jsonb;
begin
  prev := 'GENESIS'; n := 0; bad := null;
  for r in select * from selaqui.entries order by seq loop
    n := n + 1;
    body := to_jsonb(r) - 'hash' - 'prev_hash';
    if body->'extra' = 'null'::jsonb then body := body - 'extra'; end if;
    h := encode(extensions.digest(prev || '|' || body::text, 'sha256'), 'hex');
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
