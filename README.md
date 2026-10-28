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

- **Each of the 6 sites**: the same 54 document points, 10 walkthrough areas and 12 interviews = 76 points;
  456 in total.
- The 15 former group-level documents (AD-05, 09, 11, 13, 15, 17, 18, 29, 30, 37, 51, 52, 56, 59, 68) are retired.
  Findings logged against them on 28 Oct were copied into the closest DTSPL heading (e.g. AD-09 → AD-10),
  each note prefixed with its source document; the originals remain in the log as withdrawn.

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

## Auditees, client-will-share-later and the report

- **Auditees** (Sites → 👥 Auditees, or "Manage auditees" in any point form): name, designation, function,
  email and optional mobile per site, plus a corporate/common list. Edits and removals are new stamped records.
  Names are offered as suggestions when logging interviews, documents and "client will share later".
- **Client will share later** (document status): asks who will share it (pick an auditee or type), their
  mobile or email, and an expected date. Dashboard → *Client will share later* opens a follow-up list grouped
  by person with one-tap email / WhatsApp requests listing every pending document.
- **Report (PDF)** (Dashboard, Sites, Backup tab): one site or all, one day or the whole audit. Cover page,
  site visits, auditees, coverage, findings by severity, pending documents, status of every point, and the
  entry log with who / when / GPS / hash and photos. Opens the phone's print screen → *Save as PDF*.

## Photo references, editing and adding photos later

- Every photo gets a reference number per site and point in upload order: `S1-AD-01-P03` (site 1, AD-01,
  3rd photo), `C-AD-05-P01` for common documents, `S2-NOTE-P01` for site notes, `EXP-P01` for bills. Shown on
  thumbnails, the gallery, full-size view, reports, CSV (Photo_Refs) and in downloaded file names.
- **📷 Add photo** on any observation (either auditor, any device) attaches photos to that observation.
- **✎ Edit** (either auditor, on any observation) saves a new version stamped with the editor's name; the card shows the latest version with "Edited by … – history",
  and the original stays visible. Both are separate stamped records in the log and audit trail.

## Deliverables

| # | Deliverable | Where it comes from |
|---|---|---|
| 1 | Security audit checklist | Report sheet → *Checklist PDF* (all 69 documents, 10 walkthrough areas, 12 interviews, rating scales, 5×5 risk matrix) |
| 2 | Site audit report | Report sheet → *Create PDF* per site: findings with risk rating and recommendation, photos, coverage, pending documents |
| 3 | Site Security Plan | Drafted from the exported log (walkthrough observations, auditees, guarding, findings) and finalised by the auditor |
| 4 | Operational Requirement | Drafted from findings + recommendations + risk ratings, each requirement traced to its finding |
| 5 | Corporate SOP set | Drafted per SOP topic from observations tagged with that topic across all sites |

Every finding can carry a **recommendation**, a **risk rating** (likelihood × impact, 1–5 each) and one or
more **SOP topics**; these are stored in `entries.extra` and exported in the CSV/JSON.

## Expense claims

Resources → Expenses: log a reimbursement claim (category, amount, date, vendor, bill/booking no., payment
mode, description) with photos or screenshots of the bill. Each claim is stamped with who, IST time and GPS.
Status moves Not submitted → Submitted → Approved → Paid (or Rejected); every change is a new stamped
record with an optional note, so the history stays visible. Totals per person and per status, and a CSV
export for sending to Northstar. Travel cards with a booking (e.g. the Savaari cab) have a one-tap
"Log as expense claim" that pre-fills the details.

## Desktop

At 1100 px and wider the app switches to a left sidebar, multi-column dashboard, grids for sites, entries,
contacts and photos, and opens points / auditees / claims / reports in a right-hand panel beside the list.
Keyboard: `/` jumps to checklist search, `Esc` closes the panel or photo. Phones keep the bottom tab bar.

## Where photos are stored

Supabase → project **client-portal** → Storage → bucket **`selaqui-audit`** → `photos/ajay/` and `photos/anis/`.
Each file is `<entry-id>-<n>.jpg` (about 1600 px) with a `-t.jpg` thumbnail. The bucket is private.
In the app: the 📷 Photos chip in the header (or Activity → Photos) shows every photo with who took it,
IST date/time, site, point, GPS and note, and downloads it with a readable name
(`Site1_AD-01_Ajay_2026-10-28_143205_1.jpg`).

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
