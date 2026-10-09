/* =====================================================================
   La Roche — menu admin API  (Cloudflare Worker)

   Sits between the admin page and GitHub so the café owner only ever
   needs a password. The GitHub token lives here as an encrypted secret
   and never reaches the browser or the repository.

   Required
     secret  GH_TOKEN   GitHub token with write access to the repo
   Optional
     var     OWNER, REPO, BRANCH, ORIGIN   override the defaults below
     KV      KV         namespace binding; when present the password hash
                        is kept here (private) instead of in menu.json,
                        and the owner can change it from the admin page
   ===================================================================== */

const DEF = {
  owner:  "otillion",
  repo:   "laroche-menu",
  branch: "main",
  origin: "https://otillion.github.io"
};
const SESSION_HOURS = 8;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;

const cfg = (env, k) => env[k.toUpperCase()] || DEF[k];

/* ---------- plumbing ---------- */
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array((String(h).match(/../g) || []).map(x => parseInt(x, 16)));

function cors(env, extra){
  return Object.assign({
    "Access-Control-Allow-Origin": cfg(env, "origin"),
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  }, extra || {});
}
const reply = (env, obj, status) => new Response(JSON.stringify(obj),
  {status: status || 200, headers: cors(env, {"content-type": "application/json;charset=utf-8"})});

/* base64 both ways, in chunks — spreading a 20k-element array into
   String.fromCharCode overflows the stack */
function b64utf8(str){
  const b = new TextEncoder().encode(str);
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64utf8(b64){
  const bin = atob(String(b64).replace(/\s/g, ""));
  const b = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i);
  return new TextDecoder().decode(b);
}

/* constant-time compare, so a wrong password leaks nothing through timing */
function same(a, b){
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function derive(pw, saltHex, iter){
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw),
    "PBKDF2", false, ["deriveBits"]);
  return hex(await crypto.subtle.deriveBits(
    {name: "PBKDF2", salt: unhex(saltHex), iterations: iter, hash: "SHA-256"}, key, 256));
}

/* ---------- where the password lives ---------- */
async function repoMenu(env){
  const r = await gh(env, "GET", "contents/menu.json?ref=" + cfg(env, "branch"));
  if (!r.ok) throw new Error("menu.json unreadable (" + r.status + ")");
  return JSON.parse(unb64utf8((await r.json()).content));
}
async function readAuth(env){
  if (env.KV){
    const s = await env.KV.get("auth");
    if (s) return JSON.parse(s);          // private copy wins
  }
  // no KV yet: fall back to the copy inside menu.json
  const menu = await repoMenu(env);
  if (!menu.auth || !menu.auth.hash) throw new Error("no password is set");
  return menu.auth;
}
async function writeAuth(env, auth){
  if (!env.KV) throw new Error("kv-missing");
  await env.KV.put("auth", JSON.stringify(auth));
}

/* ---------- sessions ----------
   Signed with the password hash itself, so changing the password
   invalidates every outstanding session without extra bookkeeping. */
async function hmac(keyHex, msg){
  const k = await crypto.subtle.importKey("raw", unhex(keyHex),
    {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", k, new TextEncoder().encode(msg)));
}
async function issue(auth){
  const exp = Date.now() + SESSION_HOURS * 3600e3;
  return exp + "." + (await hmac(auth.hash, "v1." + exp));
}
async function check(env, token){
  const [expStr, sig] = String(token || "").split(".");
  const exp = Number(expStr);
  if (!exp || !sig || exp < Date.now()) return null;
  const auth = await readAuth(env);
  return same(await hmac(auth.hash, "v1." + exp), sig) ? auth : null;
}

/* ---------- GitHub ---------- */
function gh(env, method, path, body){
  return fetch("https://api.github.com/repos/" + cfg(env, "owner") + "/" + cfg(env, "repo") + "/" + path, {
    method,
    headers: {
      Authorization: "Bearer " + env.GH_TOKEN,
      Accept: "application/vnd.github+json",
      "User-Agent": "laroche-menu-admin",
      "content-type": "application/json"
    },
    body: body ? JSON.stringify(body) : undefined
  });
}
async function shaOf(env, path){
  const r = await gh(env, "GET", "contents/" + path + "?ref=" + cfg(env, "branch"));
  if (r.status === 404) return null;
  if (!r.ok) throw new Error("read " + path + ": " + r.status);
  return (await r.json()).sha;
}
async function put(env, path, b64, message){
  const body = {message, content: b64, branch: cfg(env, "branch")};
  const sha = await shaOf(env, path);
  if (sha) body.sha = sha;
  const r = await gh(env, "PUT", "contents/" + path, body);
  if (!r.ok){
    let m = ""; try { m = (await r.json()).message || ""; } catch (e) {}
    throw new Error(path + ": " + r.status + " " + m);
  }
}

/* only paths this API is allowed to touch */
const okPath = p => /^img\/[A-Za-z0-9._-]{1,64}$/.test(p);
const b64len = s => Math.floor(String(s).replace(/=+$/, "").length * 3 / 4);

/* ---------- routes ---------- */
async function route(req, env){
  const path = new URL(req.url).pathname.replace(/\/+$/, "") || "/";
  const body = await req.json().catch(() => ({}));

  if (path === "/login"){
    const auth = await readAuth(env);
    const got = await derive(String(body.pw || ""), auth.salt, auth.iter || 120000);
    if (!same(got, auth.hash)){
      await new Promise(r => setTimeout(r, 400));       // blunt the guessing rate
      return reply(env, {error: "bad-password"}, 401);
    }
    return reply(env, {token: await issue(auth), hours: SESSION_HOURS, kv: !!env.KV});
  }

  const auth = await check(env, body.token);
  if (!auth) return reply(env, {error: "session"}, 401);

  if (path === "/image"){
    if (!okPath(body.path)) return reply(env, {error: "bad-path"}, 400);
    if (b64len(body.b64) > MAX_IMAGE_BYTES) return reply(env, {error: "too-big"}, 413);
    await put(env, body.path, String(body.b64).replace(/\s/g, ""), "menu: add image " + body.path);
    return reply(env, {ok: true});
  }

  if (path === "/save"){
    const menu = body.menu;
    if (!menu || !Array.isArray(menu.cats) || !menu.cats.length)
      return reply(env, {error: "bad-menu"}, 400);
    for (const c of menu.cats)
      if (!c.id || !c.ar || !c.tr || !Array.isArray(c.items))
        return reply(env, {error: "bad-category"}, 400);

    // Fields the client has no business setting are carried over from the
    // published file. In particular the KV password never gets written into
    // menu.json, which is public.
    const cur = await repoMenu(env).catch(() => null);
    for (const k of ["auth", "api"]){
      if (cur && cur[k] !== undefined) menu[k] = cur[k]; else delete menu[k];
    }
    await put(env, "menu.json", b64utf8(JSON.stringify(menu, null, 1)),
      "menu: update from admin panel");
    return reply(env, {ok: true, v: menu.v});
  }

  if (path === "/password"){
    if (!env.KV) return reply(env, {error: "kv-missing"}, 501);
    const {salt, iter, hash} = body;
    if (!/^[0-9a-f]{32}$/.test(salt || "") || !/^[0-9a-f]{64}$/.test(hash || "") ||
        !(iter >= 100000 && iter <= 1000000))
      return reply(env, {error: "bad-auth"}, 400);
    await writeAuth(env, {salt, iter, hash});
    return reply(env, {ok: true});   // old sessions stop working from here
  }

  return reply(env, {error: "not-found"}, 404);
}

export default {
  async fetch(req, env){
    if (req.method === "OPTIONS") return new Response(null, {status: 204, headers: cors(env)});
    if (req.method !== "POST") return reply(env, {error: "post-only"}, 405);
    const origin = req.headers.get("Origin");
    if (origin && origin !== cfg(env, "origin")) return reply(env, {error: "origin"}, 403);
    if (!env.GH_TOKEN) return reply(env, {error: "no-token-configured"}, 500);
    try{
      return await route(req, env);
    }catch(e){
      return reply(env, {error: String(e && e.message || e)}, 500);
    }
  }
};
