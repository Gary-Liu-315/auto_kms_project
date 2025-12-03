import sqlite3
import datetime
from typing import Optional
from key_object import KeyObject, KeyStatus, KeyType, KeyUsage
import crypto_utils as cu
import hashlib
import hmac
import os
import threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from crypto_utils import validate_password

folder_path = "./rte"

if not os.path.exists(folder_path):
    os.makedirs(folder_path)

ADMIN_PASS_ENV = cu.ADMIN_PASS_ENV

class KeyStore:
    def __init__(self, db_path: str = "./rte/keystore.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(
            self.db_path,
            detect_types=sqlite3.PARSE_DECLTYPES,
            check_same_thread=False  # 允许跨线程
        )
        self.lock = threading.Lock()
        self._init_tables()
        self.current_user: Optional[str] = None

    def _init_tables(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS keys (
                    key_id TEXT PRIMARY KEY,
                    owner TEXT,
                    key_type TEXT,
                    usage TEXT,
                    status TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    encrypted_material BLOB
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    user TEXT,
                    action TEXT,
                    key_id TEXT,
                    details TEXT
                )
                """
            )
            cur.execute("PRAGMA table_info(audit)")
            cols = [r[1] for r in cur.fetchall()]
            if "user" not in cols:
                try:
                    cur.execute("ALTER TABLE audit ADD COLUMN user TEXT")
                except Exception:
                    pass

            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    salt TEXT,
                    iterations INTEGER,
                    pw_verifier TEXT,
                    enc_master BLOB
                )
                """
            )
            self.conn.commit()

    # -------------------------
    # User management
    # -------------------------
    def user_count(self) -> int:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            return cur.fetchone()[0]

    def register_first_user(self, username: str, password: str) -> None:
        ok, msg = validate_password(password, username)
        if not ok:
            raise ValueError(msg)
        if self.user_count() > 0:
            raise ValueError("Users already exist; use admin add_user or create while logged in.")

        salt = os.urandom(16)
        iterations = cu.PBKDF2_ITERS
        kek = cu._derive_key_from_passphrase(password, salt, iterations)
        verifier = hashlib.sha256(kek).hexdigest()
        master_key = cu.generate_random_bytes(cu.MASTER_KEY_SIZE)
        aes = AESGCM(kek)
        nonce = cu.generate_random_bytes(12)
        enc = aes.encrypt(nonce, master_key, None)
        enc_blob = nonce + enc

        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO users (username, salt, iterations, pw_verifier, enc_master) VALUES (?, ?, ?, ?, ?)",
                (username, salt.hex(), iterations, verifier, enc_blob),
            )
            self.conn.commit()

        cu.init_master_key_from_bytes(master_key)
        self.current_user = username
        self._log_action("USER_REGISTER", username, "Registered first user and created master key")

    def register_user(self, username: str, password: str) -> None:
        ok, msg = validate_password(password, username)
        if not ok:
            raise ValueError(msg)

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE username=?", (username,))
            if cur.fetchone():
                raise ValueError("User already exists")

        salt = os.urandom(16)
        iterations = cu.PBKDF2_ITERS
        kek = cu._derive_key_from_passphrase(password, salt, iterations)
        verifier = hashlib.sha256(kek).hexdigest()
        master_key = cu.generate_random_bytes(cu.MASTER_KEY_SIZE)
        aes = AESGCM(kek)
        nonce = cu.generate_random_bytes(12)
        enc = aes.encrypt(nonce, master_key, None)
        enc_blob = nonce + enc

        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO users (username, salt, iterations, pw_verifier, enc_master) VALUES (?, ?, ?, ?, ?)",
                (username, salt.hex(), iterations, verifier, enc_blob),
            )
            self.conn.commit()

        cu.init_master_key_from_bytes(master_key)
        self.current_user = username
        self._log_action("USER_REGISTER", username, "Registered user and created dedicated master key")

    def login_user(self, username: str, password: str) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT salt, iterations, pw_verifier, enc_master FROM users WHERE username=?", (username,))
            row = cur.fetchone()

        if not row:
            raise ValueError("User not found")

        salt_hex, iterations, verifier, enc_blob = row
        salt = bytes.fromhex(salt_hex)
        iterations = int(iterations)
        kek = cu._derive_key_from_passphrase(password, salt, iterations)
        expected = hashlib.sha256(kek).hexdigest()
        if not hmac.compare_digest(expected, verifier):
            raise PermissionError("Invalid password")

        if enc_blob is None:
            raise RuntimeError("Encrypted master key missing for user (corrupt DB)")
        nonce = enc_blob[:12]
        ct = enc_blob[12:]
        aes = AESGCM(kek)
        master_key = aes.decrypt(nonce, ct, None)

        cu.init_master_key_from_bytes(master_key)
        self.current_user = username
        self._log_action("USER_LOGIN", username, "User logged in and master key loaded")
        return True

    # -------------------------
    # Keys
    # -------------------------
    def add_key(self, kobj: KeyObject):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO keys (key_id, owner, key_type, usage, status, created_at, updated_at, encrypted_material) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                kobj.to_row(),
            )
            self.conn.commit()
        self._log_action("CREATE", kobj.key_id, f"Created {kobj.key_type.value} for {kobj.owner}")

    def create_key(self, owner: str, key_type: KeyType, key_usage: KeyUsage) -> KeyObject:
        if self.current_user is None:
            raise PermissionError("Must be logged in to create keys")
        cu.require_master_key_loaded()
        owner = self.current_user
        kobj = KeyObject(owner=owner, key_type=key_type, key_usage=key_usage)

        if key_type in (KeyType.AES_128, KeyType.AES_192, KeyType.AES_256,
                        KeyType.HMAC_SHA256, KeyType.HMAC_SHA384, KeyType.HMAC_SHA512):
            raw = cu.generate_symmetric_key_from_type(key_type.value)
            kobj.encrypted_material = cu.encrypt_with_master_key(raw)
            kobj.public_material = None
        elif key_type in (KeyType.RSA_2048, KeyType.RSA_3072, KeyType.RSA_4096):
            bits = int(key_type.value.split("-")[1])
            priv, pub = cu.generate_rsa_keypair(bits)
            package = priv + b"\n---PUBLIC---\n" + pub
            kobj.encrypted_material = cu.encrypt_with_master_key(package)
            kobj.public_material = pub.decode()
        elif key_type in (KeyType.ECC_P256, KeyType.ECC_P384, KeyType.ECC_P521):
            priv, pub = cu.generate_ecc_keypair(key_type.value)
            package = priv + b"\n---PUBLIC---\n" + pub
            kobj.encrypted_material = cu.encrypt_with_master_key(package)
            kobj.public_material = pub.decode()
        elif key_type == KeyType.ED25519:
            priv, pub = cu.generate_ed25519_keypair()
            package = priv + b"\n---PUBLIC---\n" + pub
            kobj.encrypted_material = cu.encrypt_with_master_key(package)
            kobj.public_material = pub.decode()
        else:
            raise ValueError("Unsupported key type")

        self.add_key(kobj)
        return kobj

    def import_public_key(self, owner: str, key_type: KeyType, key_usage: KeyUsage, public_pem: str) -> KeyObject:
        if self.current_user is None:
            raise PermissionError("Must be logged in to import keys")
        kobj = KeyObject(owner=self.current_user, key_type=key_type, key_usage=key_usage)
        kobj.encrypted_material = None
        kobj.public_material = public_pem
        kobj.status = KeyStatus.PRE_ACTIVE
        self.add_key(kobj)
        self._log_action("IMPORT_PUB", kobj.key_id, f"Imported public key for {self.current_user}")
        return kobj

    def update_key_status(self, key_id: str, new_status: KeyStatus) -> bool:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM keys WHERE key_id=?", (key_id,))
            row = cur.fetchone()
        if not row:
            raise ValueError("Key not found")

        kobj = KeyObject.from_row(row)
        if self.current_user is None or kobj.owner != self.current_user:
            raise PermissionError("Can only update status of keys owned by current user")

        kobj.transition(new_status)
        enc = kobj.encrypted_material
        if new_status in (KeyStatus.DESTROYED, KeyStatus.REVOKED, KeyStatus.COMPROMISED):
            enc = None

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE keys SET status=?, updated_at=?, encrypted_material=? WHERE key_id=?",
                        (kobj.status.value, datetime.datetime.utcnow().isoformat(), enc, kobj.key_id))
            self.conn.commit()
        self._log_action("STATUS", key_id, f"Transitioned to {new_status.value}")
        return True

    def export_public_key(self, key_id: str) -> Optional[str]:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT owner, encrypted_material FROM keys WHERE key_id=?", (key_id,))
            row = cur.fetchone()
        if not row or not row[1]:
            return None
        owner, enc = row[0], row[1]
        if self.current_user is None or owner != self.current_user:
            raise PermissionError("Can only export public keys for your own keys")
        material = cu.decrypt_with_master_key(enc)
        parts = material.split(b"\n---PUBLIC---\n")
        if len(parts) == 2:
            return parts[1].decode()
        return None

    def export_private_key(self, key_id: str, admin_override: bool = False, admin_pass: Optional[str] = None) -> Optional[str]:
        if not admin_override:
            raise PermissionError("Private key export is disabled")
        env = os.environ.get(ADMIN_PASS_ENV)
        if not env:
            raise PermissionError("Admin override not configured on system")
        if admin_pass is None:
            raise PermissionError("Admin password not provided")
        if not hmac.compare_digest(hashlib.sha256(admin_pass.encode()).hexdigest(),
                                   hashlib.sha256(env.encode()).hexdigest()):
            raise PermissionError("Admin password incorrect")

        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT owner, encrypted_material FROM keys WHERE key_id=?", (key_id,))
            row = cur.fetchone()
        if not row or not row[1]:
            return None
        material = cu.decrypt_with_master_key(row[1])
        parts = material.split(b"\n---PUBLIC---\n")
        return parts[0].decode()

    # -------------------------
    # Audit and listing
    # -------------------------
    def _log_action(self, action: str, key_id: str, details: str):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "INSERT INTO audit (timestamp, user, action, key_id, details) VALUES (?, ?, ?, ?, ?)",
                (datetime.datetime.utcnow().isoformat(), self.current_user or "SYSTEM", action, key_id, details),
            )
            self.conn.commit()

    def list_keys(self):
        with self.lock:
            cur = self.conn.cursor()
            if self.current_user:
                cur.execute("SELECT * FROM keys WHERE owner = ?", (self.current_user,))
            else:
                cur.execute("SELECT * FROM keys")
            rows = cur.fetchall()
        return [KeyObject.from_row(r) for r in rows]

    def get_key_row(self, key_id: str):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM keys WHERE key_id=?", (key_id,))
            return cur.fetchone()

    def get_key(self, key_id: str) -> KeyObject:
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT * FROM keys WHERE key_id=?", (key_id,))
            row = cur.fetchone()
        if not row:
            raise ValueError(f"Key {key_id} not found")
        obj = KeyObject.from_row(row)
        if self.current_user is None or obj.owner != self.current_user:
            raise PermissionError("Can only view keys owned by current user")
        return obj
