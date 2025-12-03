# kms_service.py
import base64, time, threading, secrets
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify, abort, g
from werkzeug.serving import make_server
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from os import urandom
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import traceback; traceback.print_exc()


import crypto_utils as cu
from key_store import KeyStore

DEFAULT_HOST, DEFAULT_PORT = "127.0.0.1", 5050
TOKEN_TTL = 3600  # 秒

__srv, __thread, __app, __store = None, None, None, None
__tokens: Dict[str, Dict[str, Any]] = {}
__lock = threading.Lock()

def _make_token(user: str) -> str:
    t = secrets.token_urlsafe(32)
    with __lock:
        __tokens[t] = {"user": user, "exp": time.time() + TOKEN_TTL}
    return t

def _check_token(token: str) -> Optional[str]:
    with __lock:
        info = __tokens.get(token)
        if not info or info["exp"] < time.time():
            return None
        return info["user"]

def _require_auth():
    auth = request.headers.get("Authorization", "")
    token = auth.split(" ", 1)[1] if auth.startswith("Bearer ") else None
    if token is None:
        abort(401, "Unauthorized")
    user = _check_token(token)
    if not user or not __store or user != __store.current_user:
        abort(401, "Unauthorized")
    g.kms_user = user

def _make_app(store: KeyStore) -> Flask:
    app = Flask("kms")

    @app.route("/auth/login", methods=["POST"])
    def login():
        data = request.get_json(force=True)
        if not data or "username" not in data:
            abort(400, "username required")
        if data["username"] != store.current_user:
            abort(403, "只能为当前已登录用户申请 token")
        tok = _make_token(data["username"])
        return jsonify({"token": tok, "expires_in": TOKEN_TTL})

    @app.route("/keys", methods=["GET"])
    def list_keys():
        _require_auth()
        keys = store.list_keys()
        out = []
        for k in keys:
            if hasattr(k, "key_id"):  # KeyObject
                out.append({
                    "key_id": k.key_id,
                    "type": k.key_type.value,
                    "usage": k.key_usage.value,
                    "status": k.status.value
                })
            elif isinstance(k, tuple):  # tuple from DB
                out.append({
                    "key_id": k[0],
                    "type": k[2],
                    "usage": k[3],
                    "status": k[4]
                })
        return jsonify(out)


    @app.route("/keys/<key_id>/public", methods=["GET"])
    def public(key_id):
        _require_auth()
        pub = store.export_public_key(key_id)
        if not pub:
            abort(404, "no public key")
        if isinstance(pub, bytes):
            pub = pub.decode()
        return jsonify({"public_pem": pub})



    @app.route("/keys/<key_id>/raw", methods=["GET"])
    def raw(key_id):
        _require_auth()
        row = store.get_key_row(key_id)
        if not row:
            return jsonify({"error": "密钥不存在"}), 404
        if row[1] != store.current_user:
            return jsonify({"error": "非拥有者"}), 403
        if not row[7]:
            return jsonify({"error": "密钥材料不存在"}), 404
        try:
            raw = cu.decrypt_with_master_key(row[7])
            if isinstance(raw, str):
                raw = raw.encode()
            return jsonify({"raw_b64": base64.b64encode(raw).decode()})
        except Exception as e:
            import traceback; traceback.print_exc()
            return jsonify({"error": f"解密密钥材料失败: {e}"}), 500


    

    @app.route("/keys/<key_id>/wrap", methods=["POST"])
    def wrap(key_id):
        _require_auth()
        row = store.get_key_row(key_id)
        if not row:
            return jsonify({"error": "密钥不存在"}), 404
        if row[1] != store.current_user:
            return jsonify({"error": "非拥有者"}), 403
        if not row[7]:
            return jsonify({"error": "密钥材料不存在"}), 404

        try:
            # 解密 raw
            raw = cu.decrypt_with_master_key(row[7])
            if isinstance(raw, str):
                raw = raw.encode()
            elif not isinstance(raw, bytes):
                return jsonify({"error": "密钥材料类型不支持"}), 500

            data = request.get_json(force=True)
            rec_pem = data.get("recipient_pub_pem")
            if not rec_pem:
                return jsonify({"error": "缺少 recipient_pub_pem"}), 400

            pub = serialization.load_pem_public_key(rec_pem.strip().encode())
            if not isinstance(pub, rsa.RSAPublicKey):
                return jsonify({"error": "recipient_pub_pem 不是有效的 RSA 公钥"}), 400

            # 生成随机 AES key 和 IV
            aes_key = urandom(32)
            iv = urandom(16)

            # AES 加密原始数据
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(raw) + encryptor.finalize()

            # RSA 加密 AES key
            max_len = pub.key_size // 8 - 2*32 - 2  # SHA256 OAEP
            if len(aes_key) > max_len:
                return jsonify({"error": "AES key 太长，无法用 RSA 加密"}), 400

            wrapped_key = pub.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

        except Exception as e:
            # 捕获详细异常
            import traceback
            traceback.print_exc()
            return jsonify({"error": f"包装密钥失败: {e}"}), 500

        return jsonify({
            "wrapped_key_b64": base64.b64encode(wrapped_key).decode(),
            "iv_b64": base64.b64encode(iv).decode(),
            "encrypted_data_b64": base64.b64encode(encrypted_data).decode()
        })


    return app

def _thread_fn(app, host, port):
    global __srv
    __srv = make_server(host, port, app)
    __srv.serve_forever()

def start_kms_service(store: KeyStore, host=DEFAULT_HOST, port=DEFAULT_PORT):
    global __thread, __app, __store
    if __thread and __thread.is_alive(): return
    if not store.current_user: raise RuntimeError("需要先登录后再启动服务")
    __store, __app = store, _make_app(store)
    __thread = threading.Thread(target=_thread_fn, args=(__app, host, port), daemon=True)
    __thread.start()
    print(f"[KMS] 本地服务已启动: http://{host}:{port}, 用户={store.current_user}")

def stop_kms_service():
    global __srv, __thread, __app, __store, __tokens
    if __srv: __srv.shutdown()
    if __thread: __thread.join(timeout=1)
    __srv = __thread = __app = __store = None
    with __lock: __tokens.clear()
    print("[KMS] 本地服务已停止")

if __name__ == "__main__":
    from key_store import KeyStore
    store = KeyStore()
    # 需要先设置一个当前用户
    if store.user_count() > 0:
        # 假设第一个用户登录
        row = store.conn.execute("SELECT username FROM users LIMIT 1").fetchone()
        store.login_user(row[0], "你的密码")  # 要用正确的密码
        start_kms_service(store)
        while True:
            time.sleep(1)
    else:
        print("还没有注册用户，请先通过 GUI 注册。")
