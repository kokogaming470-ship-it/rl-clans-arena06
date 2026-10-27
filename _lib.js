// RL Clans Arena v4 — كل الـ API في ملف واحد (login / callback / me / db / sync / health)
const crypto = require("crypto");

let fileCfg = {};
try { fileCfg = require("../discord-config.js"); } catch (e) {}
const pick = k => String((fileCfg && fileCfg[k]) || process.env[k] || "").trim();

const CID = pick("DISCORD_CLIENT_ID");
const SEC = pick("DISCORD_CLIENT_SECRET");
const KEY = pick("SESSION_SECRET") || (SEC ? crypto.createHash("sha256").update("rl-arena|" + SEC).digest("hex") : "");
const ADMINS = pick("ADMIN_IDS").split(",").map(s => s.trim()).filter(Boolean);
const COLS = ["rules", "schedule", "applications", "visitors", "logs"];
const MODES = ["1v1", "2v2", "3v3"];

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
let _redis;
const redis = () => {
  if (!_redis) { const { Redis } = require("@upstash/redis"); _redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN, enableAutoPipelining: true }); }
  return _redis;
};

const sign = v => crypto.createHmac("sha256", KEY).update(v).digest("base64url");
const same = (a, b) => { const x = Buffer.from(a), y = Buffer.from(b); return x.length === y.length && crypto.timingSafeEqual(x, y); };
const mk = o => { const b = Buffer.from(JSON.stringify(o)).toString("base64url"); return b + "." + sign(b); };
const cookies = h => Object.fromEntries((h || "").split(/;\s*/).filter(Boolean).map(s => { const i = s.indexOf("="); return [s.slice(0, i), s.slice(i + 1)]; }));
function sess(req) {
  if (!KEY) return null;
  const v = cookies(req.headers.cookie).rl; if (!v) return null;
  const [b, s] = v.split("."); if (!b || !s || !same(s, sign(b))) return null;
  try { const o = JSON.parse(Buffer.from(b, "base64url").toString()); return o.exp && o.exp < Date.now() ? null : o; } catch { return null; }
}
const json = (res, c, o) => { res.statusCode = c; res.setHeader("Content-Type", "application/json"); res.setHeader("Cache-Control", "no-store"); res.end(JSON.stringify(o)); };
const go = (res, to, extra) => { if (extra) res.setHeader("Set-Cookie", extra); res.statusCode = 302; res.setHeader("Location", to); res.end(); };
const avatarOf = (id, av) => av ? `https://cdn.discordapp.com/avatars/${id}/${av}.${av.startsWith("a_") ? "gif" : "png"}?size=128`
  : `https://cdn.discordapp.com/embed/avatars/${Number((BigInt(id) >> 22n) % 6n)}.png`;
const parse = v => { if (typeof v === "string") { try { return JSON.parse(v); } catch { return null; } } return v; };
const hash = async c => { const h = (await redis().hgetall(c)) || {}; return Object.entries(h).map(([id, v]) => ({ id, ...parse(v) })); };
const ck = (n, v, age) => `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;
const str = (v, n) => String(v == null ? "" : v).slice(0, n);

// "ver" بيزيد مع كل تغيير — الموقع بيسأل عنه كل كام ثانية وبيسحب البيانات بس لو اتغيّر (يوفّر طلبات Upstash)
const bump = () => redis().incr("ver");
const pushEvent = async (type, text) => {
  const ev = { id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6), type, text: str(text, 200), ts: Date.now() };
  await redis().lpush("events", JSON.stringify(ev));
  await redis().ltrim("events", 0, 59);
};
const lite = a => { const { img, ...r } = a; return { ...r, img: img ? 1 : 0 }; };
const cleanApp = d => {
  d = d || {};
  return {
    clan: str(d.clan, 60).trim(), acc: str(d.acc, 60).trim(), lead: str(d.lead, 60).trim(), rank: str(d.rank, 30).trim(),
    mem: str(d.mem, 400).trim(), since: str(d.since, 60).trim(), days: str(d.days, 120).trim(),
    mode: MODES.includes(d.mode) ? d.mode : "",
    img: typeof d.img === "string" && d.img.startsWith("data:image/") && d.img.length < 700000 ? d.img : "",
  };
};

module.exports = async (req, res, forced) => {
  const u = new URL(req.url, "http://x");
  const route = forced || (u.searchParams.get("r") || u.pathname.replace(/^\/api\/?/, "")).replace(/^\/|\/$/g, "");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const SITE = (pick("SITE_URL") || "https://" + host).replace(/\/$/, "");
  const REDIRECT = SITE + "/api/callback";
  const me = sess(req), adm = !!me && ADMINS.includes(me.id);
  const hasRedis = !!(REDIS_URL && REDIS_TOKEN);

  try {
    if (route === "health" || route === "") return json(res, 200, { ok: true, v: 4, clientId: !!CID, secret: !!SEC, session: !!KEY, redis: hasRedis, redirect: REDIRECT });

    if (route === "login") {
      if (!CID || !SEC) return go(res, "/?login=config");
      const state = crypto.randomBytes(16).toString("hex");
      const q = new URLSearchParams({ client_id: CID, redirect_uri: REDIRECT, response_type: "code", scope: "identify", state, prompt: "none" });
      return go(res, "https://discord.com/oauth2/authorize?" + q, ck("rl_s", state, 600));
    }

    if (route === "callback") {
      if (u.searchParams.get("error")) return go(res, "/?login=failed&why=denied");
      const code = u.searchParams.get("code");
      const st = cookies(req.headers.cookie).rl_s;
      if (!code) return go(res, "/?login=failed&why=nocode");
      if (!st || st !== u.searchParams.get("state")) return go(res, "/?login=failed&why=state");
      const tr = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ client_id: CID, client_secret: SEC, grant_type: "authorization_code", code, redirect_uri: REDIRECT }),
      });
      const t = await tr.json();
      if (!t.access_token) return go(res, "/?login=failed&why=" + encodeURIComponent(t.error || "token"));
      const d = await (await fetch("https://discord.com/api/users/@me", { headers: { Authorization: "Bearer " + t.access_token } })).json();
      if (!d.id) return go(res, "/?login=failed&why=user");
      const tok = mk({ id: d.id, name: d.global_name || d.username, av: d.avatar || "", exp: Date.now() + 2592000000 });
      return go(res, "/?welcome=1", [ck("rl", tok, 2592000), ck("rl_s", "", 0)]);
    }

    if (route === "logout") return go(res, "/", ck("rl", "", 0));
    if (route === "me") return json(res, 200, me ? { id: me.id, name: me.name, avatar: avatarOf(me.id, me.av), isAdmin: adm } : null);

    // ========= sync: نبض الموقع (الحضور + الإصدار + كل البيانات لما تتغيّر) =========
    if (route === "sync") {
      if (!hasRedis) return json(res, 503, { error: "no_redis" });
      const r = redis(), now = Date.now(), cv = u.searchParams.get("v");

      if (me && u.searchParams.get("hb") === "1") {
        const old = parse(await r.hget("visitors", me.id));
        const rec = { ...(old || {}), name: me.name, dc: me.name, first: (old && old.first) || now, seen: now };
        await Promise.all([
          r.hset("visitors", { [me.id]: JSON.stringify(rec) }),
          r.zadd("presence", { score: now, member: "u" + me.id }),
          r.zremrangebyscore("presence", 0, now - 86400000),
        ]);
        if (!old) { await pushEvent("join", `${me.name} انضم إلى الساحة`); await bump(); }
        else if (now - (old.seen || 0) > 1800000) { await pushEvent("visit", `${me.name} دخل الموقع`); await bump(); }
      }

      const [verRaw, ids] = await Promise.all([r.get("ver"), r.zrange("presence", now - 70000, "+inf", { byScore: true })]);
      const ver = Number(verRaw) || 0;
      const online = (ids || []).length;
      const base = { v: ver, online };
      if (adm) base.onlineIds = (ids || []).map(x => String(x).slice(1));
      if (cv === String(ver)) return json(res, 200, { ...base, same: 1 });

      const [rules, schedule, events, members] = await Promise.all([hash("rules"), hash("schedule"), r.lrange("events", 0, 29), r.hlen("visitors")]);
      const out = { ...base, rules, schedule, events: (events || []).map(parse).filter(Boolean), members: Number(members) || 0, apps: [], vis: [], logs: [] };
      if (adm) { const [a, v, l] = await Promise.all([hash("applications"), hash("visitors"), hash("logs")]); out.apps = a.map(lite); out.vis = v; out.logs = l; }
      else if (me) { const a = parse(await r.hget("applications", me.id)); if (a) out.apps = [lite({ id: me.id, ...a })]; }
      return json(res, 200, out);
    }

    // ========= db =========
    if (route === "db") {
      if (!hasRedis) return json(res, 503, { error: "no_redis" });
      if (req.method === "GET") {
        const c = u.searchParams.get("c"); if (!COLS.includes(c)) return json(res, 400, {});
        if (c === "applications" && u.searchParams.get("img")) {   // صورة إثبات الرانك — بتتحمّل لوحدها عشان الـ sync يفضل خفيف
          const id = u.searchParams.get("id") || "";
          if (!me || (!adm && id !== me.id)) return json(res, 403, {});
          const a = parse(await redis().hget(c, id));
          return json(res, 200, { img: (a && a.img) || "" });
        }
        let l = await hash(c);
        if (c === "rules" || c === "schedule") return json(res, 200, l);
        if (!me) return json(res, 401, []);
        if (!adm) l = l.filter(x => x.id === me.id && (c === "applications" || c === "visitors"));
        return json(res, 200, c === "applications" ? l.map(lite) : l);
      }
      if (req.method === "POST") {
        if (!me) return json(res, 401, {});
        let b = req.body; if (typeof b === "string") { try { b = JSON.parse(b); } catch { b = {}; } }
        const { c, id, op, data } = b || {};
        if (!COLS.includes(c) || !id || typeof id !== "string" || id.length > 80) return json(res, 400, {});
        const r = redis();
        const old = parse(await r.hget(c, id));
        const put = o => r.hset(c, { [id]: JSON.stringify(o) });
        const done = async (type, text) => { if (type) await pushEvent(type, text); await bump(); return json(res, 200, { ok: 1 }); };
        const msg = (t, a) => ({ t: str(t, 500).trim(), adm: a, ts: Date.now() });

        if (adm) {
          if (c === "applications" && op === "msg") {
            const m = msg(data && data.t, true); if (!old || !m.t) return json(res, 400, {});
            await put({ ...old, chat: [...(old.chat || []), m].slice(-300) }); return done();
          }
          if (c === "applications" && op === "closechat") {
            if (!old) return json(res, 404, {});
            const { img, ...rest } = old;
            await r.hset("logs", { [`${id}_${Date.now()}`]: JSON.stringify({ ...rest, closed: Date.now() }) });
            await put({ ...old, chatOpen: false, chat: [] }); return done();
          }
          if (op === "delete") {
            await r.hdel(c, id);
            if (c === "rules") return done("rule_del", "تم حذف أحد القوانين");
            if (c === "schedule" && old) return done("sched_del", `تم إلغاء موعد: ${old.c1} VS ${old.c2}`);
            return done();
          }
          const nd = op === "update" ? { ...(old || {}), ...data } : data;
          await put(nd);
          if (c === "rules") return done(old ? "rule_edit" : "rule_add", old ? "تم تعديل أحد القوانين" : `أضافت الإدارة قانونًا جديدًا: «${str(nd.text, 70)}»`);
          if (c === "schedule" && !old) return done("sched_add", `موعد جديد: ${nd.c1} VS ${nd.c2} (${nd.mode})`);
          if (c === "applications" && op === "update" && data && data.status === "accepted" && (!old || old.status !== "accepted")) return done("accepted", `تم قبول كلان «${nd.clan}» في البطولة 🎉`);
          return done();
        }

        // ===== مستخدم عادي =====
        if (id !== me.id || c !== "applications") return json(res, 403, {});
        if (op === "set" && (!old || old.status === "rejected")) {
          const a = cleanApp(data);
          if (!a.clan || !a.acc || !a.lead || !a.rank || !a.mode || !a.img) return json(res, 400, { error: "missing" });
          await put({ ...a, status: "review", chat: [], chatOpen: false, dc: me.name, ts: Date.now() });
          return done("apply", `${me.name} قدّم طلب دخول لكلان «${a.clan}» (${a.mode})`);
        }
        if (op === "open" && old) { await put({ ...old, chatOpen: true }); return done(); }
        if (op === "msg" && old && old.chatOpen) {
          const m = msg(data && data.t, false); if (!m.t) return json(res, 400, {});
          await put({ ...old, chat: [...(old.chat || []), m].slice(-300) }); return done();
        }
        return json(res, 403, {});
      }
    }
    json(res, 404, { error: "not_found", route });
  } catch (e) { json(res, 500, { error: String(e.message || e) }); }
};
