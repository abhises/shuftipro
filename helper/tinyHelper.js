import crypto from "crypto";

function signatureFor(raw, secret) {
  const inner = crypto
    .createHash("sha256")
    .update(secret, "utf8")
    .digest("hex");
  return crypto
    .createHash("sha256")
    .update(String(raw) + inner, "utf8")
    .digest("hex");
}

function deepClone(o) {
  return JSON.parse(JSON.stringify(o));
}

export { signatureFor, deepClone };
