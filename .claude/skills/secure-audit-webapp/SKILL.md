---
name: secure-audit-webapp
description: Playbook for building or changing a secure field-audit web app with auditor, admin and client logins, a tamper-evident audit trail, client report downloads, analytics and polished PDF/ZIP deliverables. Use when building a site like the Selaqui security audit app (Northstar Safety Systemz), or when changing its logins, access, analytics, reports or client screen.
---

# Secure audit web app - playbook

Ajay Kumar (Northstar Safety Systemz) and Claude built this during the Dixon
Selaqui security audit (28 Oct to 2 Nov 2026). It records how Ajay thinks
about such a site, the security rules it must keep, and the checks to run
before anything goes live. Follow it for any similar project.

## 1. Thought process (the "why")

- **It is evidence, not just a website.** Every observation, photo and
  download may be questioned later. Record who did what, when, where (GPS)
  and on which device, and make tampering visible.
- **The server decides; the screen only shows.** Hiding a button is never
  security. Every permission (sites, documents, dates) is checked on the server.
- **Least access, for a limited time.** Clients get only their sites and
  documents, only until a set end date, and can only download.
- **The admin controls everything from the app.** Ajay must be able to
  grant, change, extend, disable, reset and monitor without a developer or
  database console. If a step needs the database, build an admin button for it.
- **Nobody gets locked out by accident.** Destructive or irreversible steps
  ask first, and new passwords apply only after they are confirmed saved.
- **The client experience must feel finished:** a warm welcome, a clear
  risk picture first, then the reports, with no confusing choices.
- **Keep each change small and verify it.** Test on a phone screen, in
  light and dark mode, before it goes live.

## 2. Architecture that worked

- **Front end:** one `app/index.html` (installable PWA) plus `app/sw.js`,
  hosted on Netlify from the working branch.
  - Works offline: entries wait in an IndexedDB outbox and sync later.
  - On every release, bump `VERSION` in `index.html` and `CACHE` in `sw.js`.
- **Back end:** Supabase.
  - Data lives in a private schema (`selaqui`); photos and backups in a
    private storage bucket.
  - One edge function (`selaqui-audit`) does its own authentication, so it
    is deployed with `verify_jwt=false`. It is the only door to the data.
- **No secrets in the repository.** Passwords, tokens and keys never go in
  code, commits or config files. Server keys stay in Supabase function secrets.

## 3. Login and session rules

- Store passwords only as bcrypt hashes (`extensions.crypt` +
  `gen_salt('bf',10)`), never in plain text.
- Sessions use a random 64-hex token. The server stores only its SHA-256
  hash. Client sessions expire at their access end date at the latest.
- **Lockout:** after 8 wrong attempts in 15 minutes, refuse sign-in for 15
  minutes. Log every failure.
- **Roles:**
  - `admin`: Ajay, who is also an auditor.
  - `auditor`: Anis.
  - `client`: Northstar. Can download only, has per-login `perms`
    (`sites`, `items`), an `access_until` end date and can be disabled.
- When client access ends, the server returns 403 with "Your access to the
  Selaqui audit documents has ended." and the app signs out. Do not add
  "contact X to extend".
- **Password changes:**
  - Self-service: needs the current password, and signs out the person's
    other devices.
  - Admin "New password" works for anyone without the old password. It is
    a two-step flow: (1) generate a 12-character letters-and-digits
    password, shown once and kept pending as a hash for 15 minutes, with the
    old password still working; (2) it is applied only after the admin types
    **saved**. Cancel or expiry keeps the old password.
  - Leave confusable characters (0/O, 1/l/I) out of generated passwords.
- **Sign out everyone:** an admin button ends all sessions except the
  admin's current one.
- **Sharing credentials:** send them privately. Ideally send the password in
  a separate message from the username and link, and tell the person to keep
  them confidential.

## 4. Authorization (server side, every call)

- Clients have an allowlist of actions: `me`, `logout`, `pull`, `signRead`,
  `resources`, `track`. Everything else returns 403 "Not available for this login".
- `pull` returns only rows for the client's sites, plus documents common to
  all sites.
- Photo links are short-lived signed URLs, issued only for photos on the
  client's sites. A request for another site's photo gets nothing back.
- Admin-only actions (`access.*`) are checked against the server-side role,
  never against the app.
- Auditors may edit any observation, but each edit is a new version stamped
  with its author. They may withdraw only their own entries.
- **Before handing over:** prove with a test client login that it gets only
  its own data, cannot read another site's photo, gets 403 on any write, and
  is refused after its end date.

## 5. Tamper-evident audit trail

- `entries` and `activity` are hash-chained: each row's hash includes the
  previous one, and `verify_chains()` reports the first break.
- **Never delete or edit trail rows.** To "reset" someone's analytics, store
  a per-person start time (config `analytics_reset`) and have analytics
  count from it. The trail keeps everything.
- **Every event records** server time, phone time, GPS (or why it is
  missing), IP and device.
- **Events logged:** sign-ins (including failed, blocked and expired),
  entries, edits, photos, document and ZIP downloads (with time taken),
  access changes, password changes and resets, sign-out-everyone and backups.
- **Backups:** hourly (only if something changed), every day at 10 PM, and
  manual. Keep the 10 newest hourly or manual backups and every daily one.

## 6. Analytics (admin only)

- The app sends a ping every 2 minutes while open. A "session" is a run of
  activity with no gap over 15 minutes, and a new sign-in starts a new session.
- Track document and ZIP generation: which document, which site or sites,
  milliseconds taken, file count and size, and success or failure.
- **Charts:**
  - stat tiles for the totals;
  - actions per day, stacked by person;
  - active time per person;
  - documents and ZIPs generated;
  - average generation time;
  - sign-ins by IST hour.
- **How the charts are built:**
  - Tap or hover on any bar shows a tooltip.
  - Tables stay below the charts.
  - A person filter sits above them.
- **Colours** follow the person, never their rank. The palette was checked
  with the dataviz skill's validator in light and dark mode: Ajay blue,
  Anis orange, then aqua, yellow and magenta for client logins.
- After testing with a client login, reset its analytics so the real client
  starts at zero. Delete test logins and reset their analytics too.

## 7. Client screen (what the client sees)

1. A welcome card with a congratulations message and a short confetti burst
   on every sign-in and every app open, skipped if the phone has reduced motion
   turned on. It has buttons for "📊 Risk analytics" and "📥 Go to the reports".
2. The combined risk picture: totals, findings by site and risk, the 5×5 risk
   matrix, a site summary, the critical findings and the gaps that recur
   across sites.
3. A highlighted **Reports - download here** banner, plus a floating 📥
   Reports button that hides once that section is on screen.
4. **Your access:** "Please download your reports within 10 days. Your
   account access will be revoked on <date time IST>", with a live countdown.
5. Two tabs:
   - **Site-wise reports:** pick a site, open a PDF.
   - **ZIP download:** Step 1 picks the sites (one, several or all); Step 2
     ticks the items.
6. A ZIP contents tree that updates with the ticks. It shows the site number
   and name on every folder and a badge per file matching the item number.
   Long names wrap rather than being cut off.
7. **Item numbers are sequential** across the items the client can see
   (1, 2, 2.1…, 3), never 1, 5, 6. ZIP folder names follow the same numbers.

## 8. Report and deliverable rules (house style)

- **Dates and versions:**
  - Show only "Audit period: 28 Oct 2026 to 2 Nov 2026". No site visit
    dates in reports, no revision numbers and no "draft" wording.
  - Site visit dates appear only on the app's Sites screen.
- **Report order:**
  - Methodology, then the risk matrix, then critical risks (never before the
    matrix), then site details and findings.
  - Each photo sits under the point it supports, never above it.
  - Add one safeguard line: the points were discussed with the auditees
    before being included.
  - Write "observations rated Medium risk or higher" rather than "gaps", and
    "not available" rather than "could not be held" in final reports.
- **File names:**
  - One scheme everywhere, for example
    `Dixon_Selaqui_D2_Security_Audit_Report_Site1_DTSPL.pdf`.
  - The PDF save name must equal the file name used inside the ZIP.
- **Maps:** KML files contain only the site perimeter and location pin,
  never the GPS of individual observations.
- **Text:** use "-" not "–".

## 9. Release checklist

1. Make the change and bump `VERSION` and the `sw.js` `CACHE`.
2. Check every inline script parses (`node` + `new Function`).
3. Test in Playwright at phone width (412 px), in light and dark mode:
   no horizontal scroll, no page errors, and the new flow working end to end.
4. For client features, use a temporary client login, then delete it and
   reset its analytics.
5. Deploy the edge function with the full file. Test new server actions
   against a throwaway login, never a real person's password.
6. Commit to the working branch and push. Check that the live site reports
   the new `VERSION`.
7. Tell the user how to refresh, and anything they must do themselves.

## 10. Lessons learned (pitfalls to avoid)

- **postgres.js:** a text parameter cast with `::jsonb` gets JSON-encoded
  twice. Use `${JSON.stringify(x)}::text::jsonb`, or `sql.json(x)`.
- **Redraw after first sync:** a screen drawn from the cached copy before
  the first sync must redraw once data is confirmed. Otherwise it stays on
  "Loading…" when the sync finds nothing new.
- **Client top bar:** the role-specific top bar must survive background
  refreshes. The auditor bar (GPS, photos) once replaced the client's.
- **`Object.keys`** puts integer-like keys ("1", "6") first. Order lists
  from an explicit array.
- **Supabase approval prompts:** destructive SQL needs the owner's approval
  in the Claude app, and the prompt times out quickly. Never bypass it.
  Build an admin feature instead, or give the owner the SQL to run.
- **Test logins** pollute analytics: reset them after testing.
- **Credentials in chat:** never store passwords anywhere. If one is posted
  in a shared chat, regenerate it.
