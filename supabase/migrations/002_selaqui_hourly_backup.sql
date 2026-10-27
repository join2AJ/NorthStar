-- Hourly backup: pg_cron calls the edge function, which writes a JSON snapshot of all entries to storage.
create extension if not exists pg_net;
create extension if not exists pg_cron;

create or replace function selaqui.run_hourly_backup() returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform net.http_post(
    url := 'https://zfinxpsezesqzskhaqad.supabase.co/functions/v1/selaqui-audit',
    headers := jsonb_build_object('content-type','application/json',
      'x-cron-secret',(select value from selaqui.config where key='cron_secret')),
    body := '{"action":"cron"}'::jsonb,
    timeout_milliseconds := 120000);
end $$;
revoke all on function selaqui.run_hourly_backup() from public, anon, authenticated;

select cron.schedule('selaqui-hourly-backup', '0 * * * *', 'select selaqui.run_hourly_backup()');
