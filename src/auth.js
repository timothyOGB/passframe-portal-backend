// PIN hashing (PBKDF2-SHA256) and signed session tokens.
// Replaces the old model of storing a plaintext PIN and trusting
// Claude's own account gate for security. Every login now hashes
// server-side and every protected request carries a signed token
// that the Worker verifies itself.

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

function b64urlEncode(obj) {
  const json = JSON.stringify(obj);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(bytes));
}

export async function hashPin(pin, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(pin), "PBKDF2", false, ["deriveBits"]);
  const derived = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return toHex(derived);
}

export function randomSalt() {
  return toHex(crypto.getRandomValues(new Uint8Array(16)));
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return toHex(sig);
}

const SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000; // 12 hours

export async function createSessionToken(secret, user) {
  const payload = {
    email: user.email,
    role: user.role,
    isFounder: !!user.is_founder,
    exp: Date.now() + SESSION_LIFETIME_MS
  };
  const encoded = b64urlEncode(payload);
  const sig = await hmac(secret, encoded);
  return encoded + "." + sig;
}

export async function verifySessionToken(secret, token) {
  if (!token || typeof token !== "string" || !token.includes(".")) return null;
  const [encoded, sig] = token.split(".");
  const expected = await hmac(secret, encoded);
  if (expected !== sig) return null;
  let payload;
  try {
    payload = b64urlDecode(encoded);
  } catch (e) {
    return null;
  }
  if (!payload.exp || payload.exp < Date.now()) return null;
  return payload;
}

export { fromHex };
