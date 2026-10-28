-- Backup rotation: hourly only when entries changed (edge function compares max_seq),
-- newest 10 hourly/manual kept, plus a permanent daily backup at 22:00 IST.
alter table selaqui.backups add column if not exists max_seq bigint;

-- selaqui.run_backup(kind text) posts {"action":"cron","type":kind} to the selaqui-audit
-- function with the x-cron-secret header read from selaqui.config (secret not stored here).

select cron.unschedule('selaqui-hourly-backup');
select cron.schedule('selaqui-hourly-backup', '0 * * * *', $c$select selaqui.run_backup('hourly')$c$);
select cron.schedule('selaqui-daily-backup', '30 16 * * *', $c$select selaqui.run_backup('daily')$c$); -- 22:00 IST
