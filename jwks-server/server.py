"""CSCE 3550 Project 2: JWKS server backed by SQLite.

Author: Bijaya Laxmi Pokhrel (EUID: blp0196)

Stores RSA private keys in ``totally_not_my_privateKeys.db`` and serves:
  * POST /auth                  -> signed JWT (``?expired`` = expired key)
  * GET  /.well-known/jwks.json -> public keys of all unexpired private keys
All SQL uses ``?`` parameters to prevent SQL injection.
"""

import base64
import json
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

HOST = "localhost"
PORT = 8080
DB_FILE = "totally_not_my_privateKeys.db"


# ---------------------------------------------------------------------------
# Key helpers
# ---------------------------------------------------------------------------

def generate_key():
    """Create a new 2048-bit RSA private key."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def serialize_key(private_key):
    """Convert a private key to PKCS1 PEM bytes so SQLite can store it."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_key(pem):
    """Load a private key back from PEM bytes."""
    if isinstance(pem, str):
        pem = pem.encode("utf-8")
    return serialization.load_pem_private_key(pem, password=None)


def int_to_base64url(value):
    """Encode an integer as unpadded base64url (used for JWK n and e)."""
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def init_db(db_file=DB_FILE):
    """Create the DB file and the keys table if they do not exist."""
    with sqlite3.connect(db_file) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS keys("
            "kid INTEGER PRIMARY KEY AUTOINCREMENT,"
            "key BLOB NOT NULL,"
            "exp INTEGER NOT NULL)"
        )


def save_key(private_key, exp, db_file=DB_FILE):
    """Insert a key with its expiry time; returns the new kid."""
    with sqlite3.connect(db_file) as conn:
        cur = conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            (serialize_key(private_key), int(exp)),
        )
        return cur.lastrowid


def seed_keys(db_file=DB_FILE):
    """Store one expired key and one key valid for one hour."""
    now = int(time.time())
    save_key(generate_key(), now - 3600, db_file)
    save_key(generate_key(), now + 3600, db_file)


def get_key(expired=False, db_file=DB_FILE):
    """Return (kid, private_key, exp) for an expired or valid key, or None."""
    now = int(time.time())
    if expired:
        sql = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    else:
        sql = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    with sqlite3.connect(db_file) as conn:
        row = conn.execute(sql, (now,)).fetchone()
    if row is None:
        return None
    return row[0], deserialize_key(row[1]), row[2]


def get_valid_keys(db_file=DB_FILE):
    """Return a list of (kid, private_key) for every unexpired key."""
    with sqlite3.connect(db_file) as conn:
        rows = conn.execute(
            "SELECT kid, key FROM keys WHERE exp > ?", (int(time.time()),)
        ).fetchall()
    return [(kid, deserialize_key(pem)) for kid, pem in rows]


# ---------------------------------------------------------------------------
# JWT / JWKS logic
# ---------------------------------------------------------------------------

def build_jwks(db_file=DB_FILE):
    """Build the JWKS dict from all valid keys in the DB."""
    keys = []
    for kid, private_key in get_valid_keys(db_file):
        numbers = private_key.public_key().public_numbers()
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(kid),
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        })
    return {"keys": keys}


def issue_token(username="userABC", expired=False, db_file=DB_FILE):
    """Sign a JWT with a key from the DB (expired key if requested)."""
    record = get_key(expired, db_file)
    if record is None:
        return None
    kid, private_key, exp = record
    payload = {"user": username, "exp": exp}
    pem = serialize_key(private_key)
    return jwt.encode(payload, pem, algorithm="RS256",
                      headers={"kid": str(kid)})


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class JWKSHandler(BaseHTTPRequestHandler):
    """Handle the /auth and /.well-known/jwks.json endpoints."""

    db_file = DB_FILE

    def _send(self, status, body=b"", content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _not_allowed(self):
        self._send(405, b"Method Not Allowed")

    do_PUT = do_PATCH = do_DELETE = do_HEAD = _not_allowed

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/auth":
            self._not_allowed()
            return
        # Read and ignore the body (Basic auth or JSON); auth is mocked.
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        expired = "expired" in parse_qs(parsed.query, keep_blank_values=True)
        token = issue_token(expired=expired, db_file=self.db_file)
        if token is None:
            self._send(500, b"No suitable key available")
            return
        self._send(200, token.encode("utf-8"))

    def do_GET(self):
        if urlparse(self.path).path != "/.well-known/jwks.json":
            self._not_allowed()
            return
        body = json.dumps(build_jwks(self.db_file)).encode("utf-8")
        self._send(200, body, "application/json")

    def log_message(self, fmt, *args):  # keep test output quiet
        pass


def create_server(host=HOST, port=PORT, db_file=DB_FILE):
    """Set up the DB, seed keys, and return an HTTPServer instance."""
    init_db(db_file)
    seed_keys(db_file)
    JWKSHandler.db_file = db_file
    return HTTPServer((host, port), JWKSHandler)


def main():  # pragma: no cover
    server = create_server()
    print(f"JWKS server running on http://{HOST}:{PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":  # pragma: no cover
    main()
