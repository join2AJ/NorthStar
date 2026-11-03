-- Client (read-only) logins managed by the admin auditor.
-- role: 'admin' (manages access, sees analytics), 'auditor' (logs the audit), 'client' (downloads documents only).
-- perms: {"sites": ["s1",...], "items": ["1","5.2",...]} for client logins; access_until ends a client's access.
alter table selaqui.users
  add column if not exists role text not null default 'auditor',
  add column if not exists perms jsonb,
  add column if not exists access_until timestamptz,
  add column if not exists disabled boolean not null default false,
  add column if not exists created_by text,
  add column if not exists note text;
alter table selaqui.users drop constraint if exists users_role_chk;
alter table selaqui.users add constraint users_role_chk check (role in ('admin','auditor','client'));
update selaqui.users set role = 'admin' where username = 'ajay';
