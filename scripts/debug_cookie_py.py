#!/usr/bin/env python3
import argparse
import binascii
import hashlib
import subprocess
import sys

def run(cmd):
    return subprocess.check_output(cmd)

def get_keychain_password(service, account):
    cmd = ["security", "find-generic-password", "-w", "-s", service]
    if account:
        cmd += ["-a", account]
    out = run(cmd)
    if out.endswith(b"\n"):
        out = out[:-1]
    return out

def pbkdf2_key(password_bytes, iterations=1003, keylen=16):
    return hashlib.pbkdf2_hmac("sha1", password_bytes, b"saltysalt", iterations, keylen)

def decrypt_openssl(key, iv, data):
    key_hex = binascii.hexlify(key).decode("ascii")
    iv_hex = binascii.hexlify(iv).decode("ascii")
    # OpenSSL expects hex input with -K/-iv, data via stdin
    p = subprocess.Popen(
        [
            "openssl",
            "enc",
            "-d",
            "-aes-128-cbc",
            "-K",
            key_hex,
            "-iv",
            iv_hex,
            "-nopad",
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = p.communicate(data)
    if p.returncode != 0:
        raise RuntimeError(err.decode("utf-8", errors="ignore"))
    return out

def unpad_pkcs7(data):
    if not data:
        return data
    pad = data[-1]
    if pad < 1 or pad > 16:
        return data
    return data[:-pad]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", required=True)
    ap.add_argument("--host-like", default="%youtube.com%")
    ap.add_argument("--name", default="SOCS")
    ap.add_argument("--service", default="Brave Safe Storage")
    ap.add_argument("--account", default="Brave")
    ap.add_argument("--iterations", type=int, default=1003)
    args = ap.parse_args()

    sql = (
        "select hex(encrypted_value) from cookies "
        "where host_key like '{}' and name='{}' limit 1;"
    ).format(args.host_like, args.name)
    enc_hex = run(["sqlite3", "-readonly", args.db, sql]).decode("utf-8").strip()
    if not enc_hex:
        print("No cookie found", file=sys.stderr)
        sys.exit(2)

    enc = binascii.unhexlify(enc_hex)
    prefix = enc[:3]
    data = enc[3:]
    print(f"prefix={prefix.decode('ascii', errors='ignore')}")

    pw = get_keychain_password(args.service, args.account)
    key = pbkdf2_key(pw, iterations=args.iterations, keylen=16)
    iv = b" " * 16
    decrypted = decrypt_openssl(key, iv, data)
    unpadded = unpad_pkcs7(decrypted)
    print("decrypted=utf8:", unpadded.decode("utf-8", errors="replace"))

if __name__ == "__main__":
    main()
