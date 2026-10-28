// Selaqui security audit API.
// Does its own auth (username/password -> opaque session token), so deploy with verify_jwt=false.
// Data lives in the private `selaqui` schema; photos and backups in the private `selaqui-audit` bucket.
import postgres from "npm:postgres@3.4.5";
import { createClient } from "npm:@supabase/supabase-js@2.45.4";

const sql = postgres(Deno.env.get("SUPABASE_DB_URL")!, { prepare: false, max: 3, idle_timeout: 20 });
const sb = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
  auth: { persistSession: false },
});
const BUCKET = "selaqui-audit";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, x-cron-secret, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (b: unknown, status = 200) =>
  new Response(JSON.stringify(b), { status, headers: { ...CORS, "Content-Type": "application/json" } });
class HttpError extends Error {
  constructor(public status: number, msg: string) { super(msg); }
}

async function sha256(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomToken() {
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return Array.from(a).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function authUser(req: Request) {
  const h = req.headers.get("authorization") || "";
  const tok = h.startsWith("Bearer ") ? h.slice(7).trim() : "";
  if (!/^[0-9a-f]{64}$/.test(tok)) throw new HttpError(401, "Please sign in again.");
  const rows = await sql`
    select u.username, u.display_name from selaqui.sessions s join selaqui.users u using (username)
    where s.token_hash = ${await sha256(tok)} and s.expires_at > now()`;
  if (!rows.length) throw new HttpError(401, "Session expired. Please sign in again.");
  return { username: rows[0].username as string, name: rows[0].display_name as string, tokenHash: await sha256(tok) };
}

/* ---------- audit trail ---------- */
function reqMeta(req: Request) {
  const ip = (req.headers.get("x-forwarded-for") || "").split(",")[0].trim() || req.headers.get("x-real-ip") || null;
  return { ip, ua: (req.headers.get("user-agent") || "").slice(0, 300) || null };
}
function cleanGeo(g: any) {
  return g && isFinite(g.lat) && isFinite(g.lng)
    ? { lat: Number(g.lat), lng: Number(g.lng), acc: Number(g.acc) || 0, stale: !!g.stale } : null;
}
async function logActivity(req: Request, actor: string | null, action: string, target: string | null, detail: unknown, geo: unknown) {
  const m = reqMeta(req);
  const g = cleanGeo(geo);
  await sql`insert into selaqui.activity(actor, action, target, detail, geo, ip, ua)
    values (${actor}, ${action}, ${target}, ${detail == null ? null : sql.json(detail as any)}, ${g ? sql.json(g) : null}, ${m.ip}, ${m.ua})`;
}

/* ---------- validation ---------- */
const SCOPES = new Set(["G", "s1", "s2", "s3", "s4", "s5", "s6"]);
// expense = a reimbursement claim (details as JSON in body, bills as photos); claim = a status change on an expense;
// person = an auditee at a site (JSON in body); a later person record with target = earlier id replaces it.
const KINDS = new Set(["point", "note", "visit", "retract", "expense", "claim", "person"]);
const CLAIM_STATUS = new Set(["submitted", "approved", "paid", "rejected", "draft"]);
const str = (v: unknown, max: number) => (v == null || v === "" ? null : String(v).slice(0, max));
const PHOTO_RE = /^photos\/[a-z0-9-]{1,64}\/[a-z0-9-]{1,64}(-t)?\.jpg$/;

function cleanEntry(e: any, author: string) {
  if (!e || typeof e !== "object") throw new HttpError(400, "Bad entry");
  const id = String(e.id || "");
  if (!/^[a-z0-9-]{8,64}$/.test(id)) throw new HttpError(400, "Bad entry id");
  if (!KINDS.has(e.kind)) throw new HttpError(400, "Bad entry kind");
  const scope = e.scope == null ? null : String(e.scope);
  if (scope !== null && !SCOPES.has(scope)) throw new HttpError(400, "Bad scope");
  const ts = new Date(e.ts);
  if (isNaN(ts.getTime())) throw new HttpError(400, "Bad timestamp");
  const photos = Array.isArray(e.photos) ? e.photos.slice(0, 12).map((p: any) => {
    const full = String(p?.p || ""), thumb = String(p?.t || "");
    if (!PHOTO_RE.test(full) || !PHOTO_RE.test(thumb)) throw new HttpError(400, "Bad photo path");
    return { p: full, t: thumb, w: Number(p.w) || 0, h: Number(p.h) || 0, kb: Number(p.kb) || 0 };
  }) : [];
  const geo = cleanGeo(e.geo);
  const evid = Array.isArray(e.evid) ? e.evid.slice(0, 10).map((x: unknown) => String(x).slice(0, 40)) : [];
  // Optional structured extras: recommendation, risk likelihood x impact (1-5), SOP topics.
  let extra: any = null;
  if (e.extra && typeof e.extra === "object") {
    const x = e.extra, lvl = (v: unknown) => { const n = Math.round(Number(v)); return n >= 1 && n <= 5 ? n : null; };
    extra = {
      rec: str(x.rec, 4000), li: lvl(x.li), im: lvl(x.im),
      sop: Array.isArray(x.sop) ? x.sop.slice(0, 12).map((t: unknown) => String(t).slice(0, 40)) : [],
    };
    if (!extra.rec && !extra.li && !extra.im && !extra.sop.length) extra = null;
  }
  return {
    id, author, kind: e.kind, scope,
    item_id: str(e.item, 16), status: str(e.status, 24), sev: str(e.sev, 12), evid,
    ref: str(e.ref, 400), provided_by: str(e.by, 200), body: str(e.body, 8000),
    photos, geo, gerr: str(e.gerr, 80), target: str(e.target, 64), device_ts: ts.toISOString(), extra,
  };
}
const outEntry = (r: any) => ({
  id: r.id, seq: Number(r.seq), author: r.author, kind: r.kind, scope: r.scope, item: r.item_id,
  status: r.status, sev: r.sev, evid: r.evid, ref: r.ref, by: r.provided_by, body: r.body,
  photos: r.photos, geo: r.geo, gerr: r.gerr, target: r.target,
  ts: new Date(r.device_ts).toISOString(), sts: new Date(r.server_ts).toISOString(), hash: r.hash, extra: r.extra,
});
const outActivity = (r: any) => ({
  id: Number(r.id), at: new Date(r.at).toISOString(), actor: r.actor, action: r.action, target: r.target,
  detail: r.detail, geo: r.geo, ip: r.ip, ua: r.ua, hash: r.hash,
});

/* ---------- backup ---------- */
async function makeBackup(req: Request, actor: string | null, trigger: string, geo?: unknown) {
  const rows = await sql`select * from selaqui.entries order by seq`;
  const acts = await sql`select * from selaqui.activity order by id`;
  const chk = await sql`select selaqui.verify_chains() v`;
  const users = await sql`select username, display_name from selaqui.users order by username`;
  const now = new Date();
  const ist = new Date(now.getTime() + 330 * 60000).toISOString(); // IST for a readable path
  const path = `backups/${ist.slice(0, 10)}/${ist.slice(11, 13)}${ist.slice(14, 16)}-${trigger}.json`;
  const body = JSON.stringify({
    app: "selaqui-audit", version: 2, createdAt: now.toISOString(), trigger,
    users, entryCount: rows.length, chainCheck: chk[0].v, entries: rows.map(outEntry), auditTrail: acts.map(outActivity),
  });
  const { error } = await sb.storage.from(BUCKET).upload(path, new Blob([body], { type: "application/json" }), {
    contentType: "application/json", upsert: true,
  });
  if (error) throw new HttpError(500, "Backup upload failed: " + error.message);
  await sql`insert into selaqui.backups(path, entries, bytes, trigger) values (${path}, ${rows.length}, ${body.length}, ${trigger})`;
  await logActivity(req, actor, "backup.created", path, { trigger, entries: rows.length, bytes: body.length }, geo);
  return { path, entries: rows.length, bytes: body.length };
}

/* ---------- handlers ---------- */
async function handle(req: Request, b: any) {
  const action = String(b.action || "");

  if (action === "cron") {
    const cfg = await sql`select value from selaqui.config where key = 'cron_secret'`;
    if (!cfg.length || req.headers.get("x-cron-secret") !== cfg[0].value) throw new HttpError(403, "Forbidden");
    return await makeBackup(req, null, "hourly");
  }

  if (action === "login") {
    const username = String(b.username || "").toLowerCase().trim();
    const password = String(b.password || "");
    const fails = await sql`select count(*)::int n from selaqui.login_failures where username = ${username} and at > now() - interval '15 minutes'`;
    if (fails[0].n >= 8) {
      await logActivity(req, username || null, "login.blocked", null, { reason: "too many failures" }, b.geo);
      throw new HttpError(429, "Too many wrong attempts. Wait 15 minutes.");
    }
    const u = await sql`select username, display_name from selaqui.users
      where username = ${username} and pass_hash = extensions.crypt(${password}, pass_hash)`;
    if (!u.length) {
      await sql`insert into selaqui.login_failures(username) values (${username})`;
      await logActivity(req, username.slice(0, 40) || null, "login.failed", null, null, b.geo);
      throw new HttpError(401, "Wrong username or password.");
    }
    const tok = randomToken();
    await sql`insert into selaqui.sessions(token_hash, username) values (${await sha256(tok)}, ${username})`;
    await sql`delete from selaqui.sessions where expires_at < now()`;
    await logActivity(req, username, "login.ok", null, null, b.geo);
    return { token: tok, username, name: u[0].display_name };
  }

  const me = await authUser(req);

  switch (action) {
    case "me":
      return { username: me.username, name: me.name };

    case "logout":
      await sql`delete from selaqui.sessions where token_hash = ${me.tokenHash}`;
      await logActivity(req, me.username, "logout", null, null, b.geo);
      return { ok: true };

    case "password": {
      const nw = String(b.newPassword || "");
      if (nw.length < 8) throw new HttpError(400, "Use at least 8 characters.");
      const ok = await sql`select 1 from selaqui.users where username = ${me.username}
        and pass_hash = extensions.crypt(${String(b.oldPassword || "")}, pass_hash)`;
      if (!ok.length) throw new HttpError(400, "Current password is wrong.");
      await sql`update selaqui.users set pass_hash = extensions.crypt(${nw}, extensions.gen_salt('bf', 10)) where username = ${me.username}`;
      await sql`delete from selaqui.sessions where username = ${me.username} and token_hash <> ${me.tokenHash}`;
      await logActivity(req, me.username, "password.changed", null, null, b.geo);
      return { ok: true };
    }

    case "pull": {
      const since = Math.max(0, Number(b.since) || 0);
      const rows = await sql`select * from selaqui.entries where seq > ${since} order by seq limit 3000`;
      const users = await sql`select username, display_name from selaqui.users`;
      const ep = await sql`select value from selaqui.config where key = 'epoch'`;
      return { entries: rows.map(outEntry), more: rows.length === 3000, users, epoch: ep.length ? ep[0].value : "1" };
    }

    case "push": {
      const list = Array.isArray(b.entries) ? b.entries.slice(0, 200) : [];
      const clean = list.map((e: any) => cleanEntry(e, me.username));
      for (const e of clean) {
        if (e.kind === "expense") {
          let d: any;
          try { d = JSON.parse(e.body || ""); } catch { throw new HttpError(400, "Bad expense details"); }
          if (!(Number(d.amount) > 0) || Number(d.amount) > 10000000) throw new HttpError(400, "Enter an amount above zero.");
        }
        if (e.kind === "person") {
          let d: any;
          try { d = JSON.parse(e.body || ""); } catch { throw new HttpError(400, "Bad auditee details"); }
          if (!d.removed && !String(d.name || "").trim()) throw new HttpError(400, "Enter the auditee's name.");
          if (e.target) {
            const t = await sql`select kind from selaqui.entries where id = ${e.target}`;
            if (!t.length || t[0].kind !== "person") throw new HttpError(400, "That auditee was not found.");
          }
        }
        if (e.kind === "claim") {
          if (!CLAIM_STATUS.has(String(e.status))) throw new HttpError(400, "Bad claim status");
          const t = await sql`select kind from selaqui.entries where id = ${e.target}`;
          if (!t.length || t[0].kind !== "expense") throw new HttpError(400, "That expense was not found.");
        }
        if (e.kind === "retract") {
          const t = await sql`select author from selaqui.entries where id = ${e.target}`;
          if (!t.length || t[0].author !== me.username) throw new HttpError(403, "You can only withdraw your own entries.");
        }
        for (const p of e.photos) {
          if (!p.p.startsWith(`photos/${me.username}/`)) throw new HttpError(400, "Bad photo path");
        }
      }
      const saved: string[] = [];
      const m = reqMeta(req);
      for (const raw of clean) {
        const e = { ...raw, photos: sql.json(raw.photos), geo: raw.geo ? sql.json(raw.geo) : null, extra: raw.extra ? sql.json(raw.extra) : null, ip: m.ip, ua: m.ua };
        const ins = await sql`insert into selaqui.entries ${sql(e, "id", "author", "kind", "scope", "item_id", "status", "sev", "evid", "ref", "provided_by", "body", "photos", "geo", "gerr", "target", "device_ts", "ip", "ua", "extra")}
          on conflict (id) do nothing returning seq`;
        if (ins.length) {
          const action = raw.kind === "retract" ? "entry.withdrawn" : raw.kind === "visit" ? "site.check-" + (raw.status || "")
            : raw.kind === "note" ? "note.added" : raw.kind === "expense" ? "expense.added" : raw.kind === "claim" ? "claim." + raw.status
            : raw.kind === "person" ? (raw.target ? (JSON.parse(raw.body || "{}").removed ? "auditee.removed" : "auditee.updated") : "auditee.added") : "entry.added";
          await logActivity(req, me.username, action, raw.kind === "retract" || raw.kind === "claim" || (raw.kind === "person" && raw.target) ? raw.target : raw.id,
            raw.kind === "expense" ? { category: raw.item_id, ...JSON.parse(raw.body || "{}"), photos: raw.photos.length, deviceTime: raw.device_ts }
              : raw.kind === "person" ? { scope: raw.scope, ...JSON.parse(raw.body || "{}"), deviceTime: raw.device_ts }
              : { scope: raw.scope, point: raw.item_id, status: raw.status, severity: raw.sev, photos: raw.photos.length, deviceTime: raw.device_ts, gpsError: raw.gerr,
                  ...(raw.extra ? { risk: raw.extra.li && raw.extra.im ? raw.extra.li * raw.extra.im : null, recommendation: raw.extra.rec ? true : false, sop: raw.extra.sop } : {}) },
            raw.geo);
        }
        saved.push(raw.id);
      }
      return { saved };
    }

    case "signUpload": {
      const paths: string[] = (Array.isArray(b.paths) ? b.paths : []).slice(0, 24).map(String);
      const out = [];
      for (const p of paths) {
        if (!PHOTO_RE.test(p) || !p.startsWith(`photos/${me.username}/`)) throw new HttpError(400, "Bad photo path");
        const { data, error } = await sb.storage.from(BUCKET).createSignedUploadUrl(p, { upsert: true });
        if (error) throw new HttpError(500, error.message);
        out.push({ path: p, url: data.signedUrl });
      }
      if (out.length) await logActivity(req, me.username, "photo.upload", null, { files: out.map((o) => o.path) }, b.geo);
      return { uploads: out };
    }

    case "signRead": {
      const paths: string[] = (Array.isArray(b.paths) ? b.paths : []).slice(0, 200).map(String)
        .filter((p) => PHOTO_RE.test(p) || /^backups\/[0-9-]{10}\/[a-z0-9-]+\.json$/.test(p));
      if (!paths.length) return { urls: {} };
      const { data, error } = await sb.storage.from(BUCKET).createSignedUrls(paths, 6 * 3600);
      if (error) throw new HttpError(500, error.message);
      const urls: Record<string, string> = {};
      for (const d of data) if (d.signedUrl && d.path) urls[d.path] = d.signedUrl;
      const bk = paths.filter((p) => p.startsWith("backups/"));
      if (bk.length) await logActivity(req, me.username, "backup.downloaded", bk[0], null, b.geo);
      return { urls };
    }

    case "backups": {
      const rows = await sql`select id, created_at, path, entries, bytes, trigger from selaqui.backups order by id desc limit 200`;
      return { backups: rows };
    }

    case "resources": {
      // Travel details and contacts; kept on the server so they are only visible after sign-in.
      const r = await sql`select value from selaqui.config where key = 'resources'`;
      return { resources: r.length ? JSON.parse(r[0].value) : null };
    }

    case "backupNow":
      return await makeBackup(req, me.username, "manual-" + me.username, b.geo);

    case "trail": {
      const before = Number(b.before) || 0;
      const rows = before
        ? await sql`select * from selaqui.activity where id < ${before} order by id desc limit 300`
        : await sql`select * from selaqui.activity order by id desc limit 300`;
      const chk = await sql`select selaqui.verify_chains() v`;
      return { activity: rows.map(outActivity), check: chk[0].v };
    }

    default:
      throw new HttpError(400, "Unknown action");
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "POST only" }, 405);
  try {
    const b = await req.json().catch(() => ({}));
    return json(await handle(req, b));
  } catch (e) {
    const status = e instanceof HttpError ? e.status : 500;
    if (status === 500) console.error(e);
    return json({ error: e instanceof Error ? e.message : "Server error" }, status);
  }
});
