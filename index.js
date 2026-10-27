// RL Clans Arena — كل الـ API في ملف واحد (login / callback / me / db / health)
const crypto = require("crypto");

let fileCfg = {};
try { fileCfg = require("../discord-config.js"); } catch (e) {}
const pick = k => String((fileCfg && fileCfg[k]) || process.env[k] || "").trim();

const CID = pick("DISCORD_CLIENT_ID");
const SEC = pick("DISCORD_CLIENT_SECRET");
// لو مفيش SESSION_SECRET بنولّده تلقائياً من الـ Client Secret — يعني تحط الاتنين بس وخلاص
const KEY = pick("SESSION_SECRET") || (SEC ? crypto.createHash("sha256").update("rl-arena|" + SEC).digest("hex") : "");
const ADMINS = pick("ADMIN_IDS").split(",").map(s => s.trim()).filter(Boolean);
const COLS = ["rules", "schedule", "applications", "visitors", "logs"];

const REDIS_URL = process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL;
const REDIS_TOKEN = process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN;
let _redis;
const redis = () => {
  if (!_redis) { const { Redis } = require("@upstash/redis"); _redis = new Redis({ url: REDIS_URL, token: REDIS_TOKEN }); }
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
const parse = v => (typeof v === "string" ? JSON.parse(v) : v);
const hash = async c => { const h = (await redis().hgetall(c)) || {}; return Object.entries(h).map(([id, v]) => ({ id, ...parse(v) })); };
const ck = (n, v, age) => `${n}=${v}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${age}`;

module.exports = async (req, res) => {
  const u = new URL(req.url, "http://x");
  // المسار يجي من الـ rewrite (?r=login) أو من الرابط الأصلي — الاتنين شغالين
  const route = (u.searchParams.get("r") || u.pathname.replace(/^\/api\/?/, "")).replace(/^\/|\/$/g, "");
  const host = req.headers["x-forwarded-host"] || req.headers.host;
  const SITE = (pick("SITE_URL") || "https://" + host).replace(/\/$/, "");
  const REDIRECT = SITE + "/api/callback";
  const me = sess(req), adm = !!me && ADMINS.includes(me.id);

  try {
    if (route === "health" || route === "") return json(res, 200, { ok: true, clientId: !!CID, secret: !!SEC, session: !!KEY, redis: !!(REDIS_URL && REDIS_TOKEN), redirect: REDIRECT });

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

    if (route === "db") {
      if (!REDIS_URL || !REDIS_TOKEN) return json(res, 503, { error: "no_redis" });
      if (req.method === "GET") {
        const c = u.searchParams.get("c"); if (!COLS.includes(c)) return json(res, 400, {});
        let l = await hash(c);
        if (c === "rules" || c === "schedule") return json(res, 200, l);
        if (!me) return json(res, 401, []);
        if (!adm) l = l.filter(x => x.id === me.id && (c === "applications" || c === "visitors"));
        return json(res, 200, l);
      }
      if (req.method === "POST") {
        if (!me) return json(res, 401, {});
        let b = req.body; if (typeof b === "string") b = JSON.parse(b);
        const { c, id, op, data } = b || {}; if (!COLS.includes(c) || !id) return json(res, 400, {});
        const cur = await redis().hget(c, id); const old = cur ? parse(cur) : null;
        const put = o => redis().hset(c, { [id]: JSON.stringify(o) });
        if (adm) {
          if (op === "delete") await redis().hdel(c, id);
          else await put(op === "update" ? { ...(old || {}), ...data } : data);
          return json(res, 200, { ok: 1 });
        }
        if (id !== me.id) return json(res, 403, {});
        if (c === "visitors") { await put({ ...(old || {}), ...data, name: me.name, dc: me.name }); return json(res, 200, { ok: 1 }); }
        if (c === "applications") {
          if (op === "set" && !old) { await put({ ...data, status: "review", chat: [], chatOpen: false, dc: me.name }); return json(res, 200, { ok: 1 }); }
          if (op === "update" && old && old.chatOpen && Array.isArray(data.chat)) {
            const extra = data.chat.slice(old.chat.length, old.chat.length + 1).map(m => ({ t: String(m.t).slice(0, 500), adm: false, ts: Date.now() }));
            await put({ ...old, chat: [...old.chat, ...extra] }); return json(res, 200, { ok: 1 });
          }
          if (op === "update" && old && data.chatOpen === true && Object.keys(data).length === 1) { await put({ ...old, chatOpen: true }); return json(res, 200, { ok: 1 }); }
        }
        return json(res, 403, {});
      }
    }
    json(res, 404, { error: "not_found", route });
  } catch (e) { json(res, 500, { error: String(e.message || e) }); }
};
