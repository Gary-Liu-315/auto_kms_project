import os
import sys
import secrets
import hmac
import hashlib
import json
import ctypes
from typing import Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.backends import default_backend

# Files
MASTER_KEY_FILE = "master.key"           # legacy unprotected master key (if present)
MASTER_KEY_PROTECTED_FILE = "master.key.enc"  # encrypted master key (if using passphrase)
MASTER_KEY_PROTECTED_META = "master.key.meta"  # stores salt and iterations
MASTER_KEY_HMAC_FILE = "master.key.hmac"  # optional integrity HMAC for unprotected master key
MASTER_KEY_SIZE = 32  # bytes (256-bit)
PBKDF2_ITERS = 200_000  # reasonable default for PBKDF2; tune per environment

# Admin override via environment (optional)
# WARNING: storing admin password in env is risky; prefer secure secret store
ADMIN_PASS_ENV = "KMS_ADMIN_PASS"


# -------------------------
# RNG: prefer OpenSSL RAND_bytes (FIPS capable) then secrets
# -------------------------
_libcrypto = None
_try_libcrypto = False


def _load_libcrypto():
    global _libcrypto, _try_libcrypto
    if _try_libcrypto:
        return _libcrypto
    _try_libcrypto = True
    candidates = []
    if sys.platform.startswith("win"):
        candidates = ["libcrypto-1_1-x64.dll", "libcrypto-1_1.dll", "libcrypto.dll", "libssl-1_1.dll"]
    elif sys.platform.startswith("darwin"):
        candidates = ["libcrypto.dylib", "libcrypto.1.1.dylib", "libcrypto.3.dylib"]
    else:
        candidates = ["libcrypto.so", "libcrypto.so.1.1", "libcrypto.so.3"]

    for name in candidates:
        try:
            _libcrypto = ctypes.CDLL(name)
            # RAND_bytes signature int RAND_bytes(unsigned char *buf, int num);
            if not hasattr(_libcrypto, "RAND_bytes"):
                _libcrypto = None
            else:
                return _libcrypto
        except Exception:
            _libcrypto = None
    return _libcrypto


def generate_random_bytes(n: int) -> bytes:
    """
    Generate cryptographically secure random bytes.
    Try OpenSSL RAND_bytes first (suitable for FIPS builds), fallback to secrets.token_bytes.
    """
    lib = _load_libcrypto()
    if lib is not None:
        buf = (ctypes.c_ubyte * n)()
        res = lib.RAND_bytes(buf, n)
        if res == 1:
            return bytes(buf)
    # fallback
    return secrets.token_bytes(n)


# -------------------------
# Master key storage / protection
# -------------------------
def _derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = PBKDF2_ITERS) -> bytes:
    """Derive a 256-bit key from passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=MASTER_KEY_SIZE, salt=salt, iterations=iterations, backend=default_backend())
    return kdf.derive(passphrase.encode("utf-8"))


def protect_master_key_with_passphrase(master_key: bytes, passphrase: str, iterations: int = PBKDF2_ITERS):
    """
    Protect master key with user passphrase.
    Writes MASTER_KEY_PROTECTED_FILE (AES-GCM encrypted) and MASTER_KEY_PROTECTED_META (json with salt & iterations).
    """
    salt = generate_random_bytes(16)
    kek = _derive_key_from_passphrase(passphrase, salt, iterations)
    aesgcm = AESGCM(kek)
    nonce = generate_random_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, master_key, None)
    with open(MASTER_KEY_PROTECTED_FILE, "wb") as f:
        f.write(nonce + ciphertext)
    meta = {"salt": salt.hex(), "iterations": iterations}
    with open(MASTER_KEY_PROTECTED_META, "w", encoding="utf-8") as f:
        json.dump(meta, f)


def load_master_key_with_passphrase(passphrase: str) -> bytes:
    """
    Load and decrypt protected master key using passphrase.
    Raises ValueError on failure.
    """
    if not os.path.exists(MASTER_KEY_PROTECTED_FILE) or not os.path.exists(MASTER_KEY_PROTECTED_META):
        raise ValueError("Protected master key files missing")
    with open(MASTER_KEY_PROTECTED_META, "r", encoding="utf-8") as f:
        meta = json.load(f)
    salt = bytes.fromhex(meta["salt"])
    iterations = int(meta.get("iterations", PBKDF2_ITERS))
    kek = _derive_key_from_passphrase(passphrase, salt, iterations)
    with open(MASTER_KEY_PROTECTED_FILE, "rb") as f:
        blob = f.read()
    nonce = blob[:12]
    ciphertext = blob[12:]
    aesgcm = AESGCM(kek)
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError("Incorrect passphrase or corrupted master key") from e


def save_legacy_master_key(master_key: bytes):
    """Save master key in legacy plain file and HMAC for integrity (compatibility)."""
    with open(MASTER_KEY_FILE, "wb") as f:
        f.write(master_key)
    # generate HMAC to detect tampering
    mac = hmac.new(b"KMS-INTEGRITY-KEY", master_key, hashlib.sha256).hexdigest().encode()
    with open(MASTER_KEY_HMAC_FILE, "wb") as f:
        f.write(mac)


def verify_legacy_master_key(master_key: bytes):
    """Verify HMAC for legacy master key; create HMAC file if missing."""
    if not os.path.exists(MASTER_KEY_HMAC_FILE):
        save_legacy_master_key(master_key)
        return True
    with open(MASTER_KEY_HMAC_FILE, "rb") as f:
        stored = f.read().strip()
    mac = hmac.new(b"KMS-INTEGRITY-KEY", master_key, hashlib.sha256).hexdigest().encode()
    if not hmac.compare_digest(mac, stored):
        raise ValueError("Legacy master key integrity check failed")


# Public API: load_or_create_master_key(passphrase=None, protect_with_passphrase=False)
def load_or_create_master_key(passphrase: Optional[str] = None, protect_with_passphrase: bool = False) -> Tuple[bytes, bool]:
    """
    Load existing master key.
    - If protected files present, passphrase required (raise if wrong).
    - If none present, create new master key.
    - If protect_with_passphrase=True and passphrase provided, save protected master key.
    Returns (master_key_bytes, is_protected_bool)
    """
    # protected flow
    if os.path.exists(MASTER_KEY_PROTECTED_FILE) and os.path.exists(MASTER_KEY_PROTECTED_META):
        if not passphrase:
            raise ValueError("Passphrase required to unlock protected master key")
        mk = load_master_key_with_passphrase(passphrase)
        return mk, True

    # legacy file present
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE, "rb") as f:
            mk = f.read()
        verify_legacy_master_key(mk)
        # optionally re-protect
        if protect_with_passphrase:
            if not passphrase:
                raise ValueError("Passphrase required to protect master key")
            protect_master_key_with_passphrase(mk, passphrase)
            # remove legacy
            try:
                os.remove(MASTER_KEY_FILE)
                os.remove(MASTER_KEY_HMAC_FILE)
            except Exception:
                pass
            return mk, True
        return mk, False

    # create new master key
    mk = generate_random_bytes(MASTER_KEY_SIZE)
    if protect_with_passphrase:
        if not passphrase:
            raise ValueError("Passphrase required to protect master key")
        protect_master_key_with_passphrase(mk, passphrase)
        return mk, True
    else:
        save_legacy_master_key(mk)
        return mk, False


# We'll keep a module-level cached master_key (may be set by caller via init_master_key)
_master_key = None
_master_key_protected = False


def init_master_key(passphrase: Optional[str] = None, protect_with_passphrase: bool = False):
    """
    Initialize module master key. Call at program start.
    If protected master key exists, must provide passphrase.
    """
    global _master_key, _master_key_protected
    mk, prot = load_or_create_master_key(passphrase=passphrase, protect_with_passphrase=protect_with_passphrase)
    _master_key = mk
    _master_key_protected = prot


def init_master_key_from_bytes(master_key: bytes):
    """
    Directly set master key from provided bytes (used when another subsystem
    decrypts the master key for a logged-in user).
    """
    global _master_key, _master_key_protected
    if not isinstance(master_key, (bytes, bytearray)) or len(master_key) != MASTER_KEY_SIZE:
        raise ValueError("Invalid master key length")
    _master_key = bytes(master_key)
    _master_key_protected = False


def require_master_key_loaded():
    if _master_key is None:
        raise RuntimeError("Master key not initialized. Call init_master_key(passphrase=...) or init_master_key_from_bytes(...) at startup.")


# -------------------------
# Encrypt / Decrypt for key material
# -------------------------
def encrypt_with_master_key(plaintext: bytes) -> bytes:
    """
    Encrypt arbitrary bytes with master key (AES-GCM).
    Stores nonce || tag || ciphertext.
    """
    require_master_key_loaded()
    if _master_key is None:
        raise RuntimeError("Master key not initialized")
    aesgcm = AESGCM(_master_key)
    nonce = generate_random_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    # return nonce || ct where ct includes tag at end for AESGCM; to be consistent we store nonce + ct
    return nonce + ct


def decrypt_with_master_key(blob: bytes) -> bytes:
    """Decrypt blob produced by encrypt_with_master_key."""
    require_master_key_loaded()
    if _master_key is None:
        raise RuntimeError("Master key not initialized")
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(_master_key)
    return aesgcm.decrypt(nonce, ct, None)


# -------------------------
# Symmetric key generation helpers
# -------------------------
def generate_symmetric_key_from_type(key_type_str: str) -> bytes:
    """Return raw symmetric key bytes according to key_type string."""
    kt = key_type_str.upper()
    if "AES-128" in kt:
        return generate_random_bytes(16)
    if "AES-192" in kt:
        return generate_random_bytes(24)
    if "AES-256" in kt:
        return generate_random_bytes(32)
    if "HMAC-SHA256" in kt:
        return generate_random_bytes(32)
    if "HMAC-SHA384" in kt:
        return generate_random_bytes(48)
    if "HMAC-SHA512" in kt:
        return generate_random_bytes(64)
    raise ValueError(f"Unknown symmetric key type: {key_type_str}")


# -------------------------
# Asymmetric key generation helpers
# -------------------------
def generate_rsa_keypair(bits: int = 2048) -> Tuple[bytes, bytes]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def generate_ecc_keypair(curve_name: str = "ECC-P256") -> Tuple[bytes, bytes]:
    cmap = {
        "ECC-P256": ec.SECP256R1(),
        "ECC-P384": ec.SECP384R1(),
        "ECC-P521": ec.SECP521R1()
    }
    if curve_name not in cmap:
        raise ValueError("Unsupported ECC curve")
    priv = ec.generate_private_key(cmap[curve_name], backend=default_backend())
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem


def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    priv = ed25519.Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.PKCS8,
                                  encryption_algorithm=serialization.NoEncryption())
    pub_pem = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv_pem, pub_pem

# 常见弱口令（可以自己扩展）
COMMON_PASSWORDS = {
    "123456","123456789","12345","12345678","1234567","1234567890","111111","123123",
    "password","password1","qwerty","abc123","1234","1q2w3e","iloveyou","123321","654321",
    "666666","7777777","123qwe","123456a","1qaz2wsx","qwertyuiop","monkey","dragon",
    "letmein","baseball","football","shadow","master","sunshine","ashley","bailey","passw0rd",
    "superman","michael","freedom","qazwsx","whatever","trustno1","welcome","login","flower",
    "hottie","lovely","zaq1zaq1","loveme","zaq12wsx","metallica","starwars","donald","password123",
    "batman","ninja","mustang","password!","killer","soccer","princess","qwerty123","pokemon",
    "charlie","andrew","michelle","11111111","131313","password11","12345678a","555555",
    "hello","66666666","secret","1q2w3e4r","qwerty1","123abc","q1w2e3r4","zaq1qaz1",
    "google","welcome1","password12","1111111","888888","121212","696969","147258369",
    "1111111111","55555555","loveyou","flower1","asdfgh","asdfghjkl","qawsed","qwert",
    "!@#$%^&*","asdf1234","777777","88888888","000000","00000000","112233","123456789a",
    "pass123","passw0rd1","admin123","123098","p@ssw0rd","1q2w3e4r5t","azerty","zaq!@WSX",
    "hello123","1qaz2wsx3edc","1q2w3e","love123","freedom1","maggie","cheese","internet",
    "summer","winter","spring","autumn","summer2020","iloveu","qazwsxedc","77777777",
    "147258","159753","qwer1234","qazxsw","asdfg","iloveyou1","pass","0000","1212","1314",
    "8888","5555","222222","333333","444444","999999","11223344","qwe123","qweasd","qweqwe",
    "1q2w3e4r5t6y","q1w2e3r","zaq123","1qaz2wsx3","987654321","54321","852147","147852",
    "qazwsx123","1q2w3e4r!","love","12345678910","1q2w3e4","asdf","admin1","root","toor",
    "god","pass1234","user","manager","welcome123","welcome2021","welcome2022","0000000000",
    "abc123456","abc12345","qaz123","zaq12wsx34","q1w2e3r4t5","qazwsxedcrfv","123456qq","liverpool",
    "chelsea","arsenal","qweqweqwe","qqqqqq","zzzzzz","111222","iloveyou2","password2","1qazxsw2",
    "zaq1zaq1","pokemon123","pokemon1","hacker","shadow1","letmein1","adminadmin","adobe123",
    "adobe","college","student","computer","desktop","notebook","internet123","master123",
    "access","love1234","qazxsw123","!@#123","passw","welcome!","1111","2222","3333","4444",
    "9999","00000","12121212","147852369","qwertyui","qwerty12","1qaz2wsx3edc4rfv","pass12345"
}

def is_sequential(pw: str) -> bool:
    """检测是否为顺序字符，例如 123456, abcdef"""
    sequences = ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
    pw_lower = pw.lower()
    for seq in sequences:
        if pw_lower in seq or pw_lower[::-1] in seq:
            return True
    return False

def validate_password(password: str, username: Optional[str] = None) -> Tuple[bool, str]:
    if len(password) < 6:
        return False, "密码长度必须大于等于6位"
    if username and username.lower() in password.lower():
        return False, "密码不能包含用户名"
    if password.lower() in COMMON_PASSWORDS:
        return False, "密码过于常见，存在弱口令风险"
    if password.isdigit():
        return False, "密码不能为纯数字"
    if len(set(password)) == 1:
        return False, "密码不能为重复字符"
    if is_sequential(password):
        return False, "密码不能为连续字符"
    return True, ""
