# Selaqui security audit log

Field app for the Northstar security audit of six Dixon sites at Selaqui, Dehradun.
Two auditors (Ajay Kumar, Anis Rao) log on their own phones; every entry is shared, stamped with
who, when and GPS, and can carry photos.

## What's where

| Path | What it is |
|---|---|
| `app/` | The web app (single `index.html`, offline shell `sw.js`). Deployed to Netlify. |
| `netlify.toml` | Netlify config: publishes `app/`. |
| `supabase/functions/selaqui-audit/` | API: login, sync, photo upload links, backups. Deployed with `verify_jwt = false` (does its own auth). |
| `supabase/migrations/` | Database setup in the `client-portal` Supabase project, schema `selaqui`, bucket `selaqui-audit`. |

## Audit content

- **Common documents**: 15 document points collected once for all sites.
- **Each of the 6 sites**: 54 document points (AD-xx, from the 69-item requisition), 10 walkthrough
  areas (W-xx, from the Scope of Work) and 12 stakeholder interviews (I-xx, from the requisition).
- 471 points in total.

## What every log records

Each entry is stamped with: who logged it (taken from the signed-in session, not typed), phone date and
time to the second, server receive time, GPS latitude/longitude with accuracy (or the reason there is no
fix), IP and device, a record ID and a SHA-256 hash linking it to the previous record. All times show in IST.

## Audit trail

Activity tab → Audit trail lists every action on the server: sign-ins, failed sign-ins, blocked sign-ins,
sign-outs, password changes, entries, notes, withdrawals, check-in/out, photo uploads, backups created and
downloaded. The log tables are append-only in the database (updates and deletes are rejected), and both are
hash-chained; the app re-checks the chain each time the trail is opened and shows "Chain intact" or the
first broken record. The trail is included in every hourly backup and can be exported as CSV.

## How data is kept safe

- Entries are append-only. Nothing is overwritten; a wrong entry is *withdrawn* by its author and stays visible.
- Entries and photos save on the phone first (IndexedDB) and upload when there is signal.
- Photos are compressed on the phone (about 1600 px, roughly 200–350 KB) with a small thumbnail.
- A JSON snapshot of all entries is written to `selaqui-audit/backups/` every hour by `pg_cron`.
  The Backup tab lists them and can trigger one on demand.

## Deploy the app to Netlify

Netlify → Add new site → Import from Git → pick this repo and branch. Build command: none.
Publish directory: `app` (already set in `netlify.toml`). Or drag the `app` folder onto
app.netlify.com/drop.
