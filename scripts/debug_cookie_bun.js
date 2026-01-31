#!/usr/bin/env bun
import { execSync } from "node:child_process";
import { pbkdf2Sync, createDecipheriv } from "node:crypto";

function getKeychainPassword(service, account) {
  const args = ["security", "find-generic-password", "-w", "-s", service];
  if (account) args.push("-a", account);
  const out = execSync(args.join(" "));
  let buf = Buffer.from(out);
  if (buf.length && buf[buf.length - 1] === 0x0a) buf = buf.subarray(0, -1);
  return buf;
}

function unpadPkcs7(buf) {
  if (!buf.length) return buf;
  const pad = buf[buf.length - 1];
  if (pad < 1 || pad > 16) return buf;
  return buf.subarray(0, buf.length - pad);
}

const db = process.argv[2];
const hostLike = process.argv[3] || "%youtube.com%";
const name = process.argv[4] || "SOCS";
const service = process.argv[5] || "Brave Safe Storage";
const account = process.argv[6] || "";
const iterations = Number(process.argv[7] || 1003);

if (!db) {
  console.error("Usage: debug_cookie_bun.js <db> [hostLike] [name] [service] [account] [iterations]");
  process.exit(2);
}

const sql = `select hex(encrypted_value) from cookies where host_key like '${hostLike}' and name='${name}' limit 1;`;
const encHex = execSync(`sqlite3 -readonly \"${db}\" \"${sql}\"`).toString("utf8").trim();
if (!encHex) {
  console.error("No cookie found");
  process.exit(2);
}
const enc = Buffer.from(encHex, "hex");
console.log("prefix=", enc.subarray(0, 3).toString());

const pw = getKeychainPassword(service, account);
const key = pbkdf2Sync(pw, "saltysalt", iterations, 16, "sha1");
const data = enc.subarray(3);
const iv = Buffer.alloc(16, " ");
const decipher = createDecipheriv("aes-128-cbc", key, iv);
decipher.setAutoPadding(false);
const decoded = Buffer.concat([decipher.update(data), decipher.final()]);
const unpadded = unpadPkcs7(decoded);
console.log("decrypted=utf8:", unpadded.toString("utf8"));
