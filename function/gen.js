export const onRequestGet = async (ctx) => {
  const secret = ctx.env.SECRET_KEY; // set di Pages → Settings → Environment Variables
  if (!secret) return new Response(JSON.stringify({err:"SECRET_KEY missing"}), {status:500});

  const now = Math.floor(Date.now()/1000);
  const exp = now + 24*60*60; // 24 jam
  const payload = `${exp}`;    // cukup timestamp expire (detik)

  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name:"HMAC", hash:"SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(payload));
  const sig = b64url(new Uint8Array(sigBuf));

  const token = `FREE-${b64urlString(payload)}.${sig}`;
  return json({ key: token, exp });
};

function b64urlString(s){ return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function b64url(bytes){ let bin=""; bytes.forEach(b=>bin+=String.fromCharCode(b));
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); }
function json(obj){ return new Response(JSON.stringify(obj), {headers:{'content-type':'application/json'}}); }

