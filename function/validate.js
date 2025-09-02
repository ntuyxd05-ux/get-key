export const onRequestGet = async (ctx) => {
  const secret = ctx.env.SECRET_KEY;
  const url = new URL(ctx.request.url);
  const token = url.searchParams.get("key") || "";

  const bad = (msg) => json({ ok:false, err: msg });

  if (!secret) return bad("server-missing-secret");
  if (!/^FREE-[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(token)) return bad("format");

  const [head, body] = token.split("FREE-")[1].split(".");
  const payload = atob(head.replace(/-/g,'+').replace(/_/g,'/'));
  const exp = parseInt(payload,10);
  if (!Number.isFinite(exp)) return bad("payload");

  // recompute signature
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(`${exp}`));
  const sig = b64url(new Uint8Array(sigBuf));
  if (sig !== body) return bad("signature");

  const now = Math.floor(Date.now()/1000);
  if (now > exp) return bad("expired");

  return json({ ok:true, exp });
};

function b64url(bytes){ let bin=""; bytes.forEach(b=>bin+=String.fromCharCode(b));
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/, ''); }
function json(obj){ return new Response(JSON.stringify(obj), {headers:{'content-type':'application/json'}}); }

