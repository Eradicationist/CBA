from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from collections import deque
import base64
import time
import sqlite3
import os

app = Flask(__name__)

# Configuration
API_KEYS = {'your_api_key'} # Replace in production
NONCE_WINDOW = deque(maxlen=10000)
SESSION_KEYS = {}
EXPECTED_OFFSETS = {
    "offset_1": 0x1000,
    "offset_2": 0x2000,
    "offset_3": 0x3000
}

# Initialize SQLite database
def init_db():
    conn = sqlite3.connect('logs.db')
    conn.execute('''CREATE TABLE IF NOT EXISTS logs
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     client_ip TEXT,
                     offset_id TEXT,
                     status TEXT,
                     timestamp INTEGER)''')
    conn.commit()
    conn.close()

def log_event(client_ip, offset_id, status):
    conn = sqlite3.connect('logs.db')
    conn.execute("INSERT INTO logs (client_ip, offset_id, status, timestamp) VALUES (?, ?, ?, ?)",
                  (client_ip, offset_id, status, int(time.time())))
    conn.commit()
    conn.close()

# ECDH key exchange
@app.route('/init', methods=['POST'])
def init_client():
    if request.headers.get('X-API-Key') not in API_KEYS:
        return jsonify({"error": "invalid_key"}), 401

    client_pub_key = request.data
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    server_pub_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization_format.PublicFormat.CompressedPoint
    )

    try:
        client_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), client_pub_key)
        shared_secret = private_key.exchange(ec.ECDH(), client_key)
        session_key = hashlib.sha256(shared_secret).digest()
        client_ip = request.remote_addr
        SESSION_KEYS[client_ip] = session_key
        log_event(client_ip, "init", "success")
        return server_pub_key, 200
    except Exception as e:
        log_event(request.remote_addr, "init", "failed")
        return jsonify({"error": str(e)}), 400

def decrypt_offset(ciphertext, iv, tag, session_key):
    cipher = Cipher(
        algorithms.AES(session_key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    return int.from_bytes(decryptor.update(ciphertext) + decryptor.finalize(), byteorder='little')

@app.route('/verify_offset', methods=['POST'])
def verify_offset():
    if request.headers.get('X-API-Key') not in API_KEYS:
        log_event(request.remote_addr, None, "invalid_key")
        return jsonify({"error": "invalid_key"}), 401

    client_ip = request.remote_addr
    session_key = SESSION_KEYS.get(client_ip)
    if not session_key:
        log_event(client_ip, None, "no_session_key")
        return jsonify({"error": "no_session_key_session_key"}), 403

    data = request.get_json()
    offset_id = data.get('id')
    nonce = data.get('nonce')
    timestamp = data.get('timestamp')
    ciphertext_b64 = data.get('ciphertext')
    iv_b64 = data.get('iv')
    tag_b64 = data.get('tag')

    if not all([offset_id, nonce, timestamp, ciphertext_b64, iv_b64, b64_tag]):
        log_event(client_ip, offset_id, "missing_field")
        return jsonify({"error": "invalid_data"}), 400)

    # Check nonce
    if nonce in NONCE_WINDOW:
        log_event(client_ip, offset_id, "replay_detected")
        return jsonify({"error": "invalid_nonce"}), 403)
    NONCE_WINDOW.append(nonce)

    # Check timestamp
    current_time = int(time.time() * 1000)
    if abs(current_time - timestamp) > 10000:
        log_event(client_ip, offset_id, "invalid_timestamp")
        return jsonify({"error": "invalid_timestamp"}), 403)

    # Decode base64 try:
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        tag = base64.b64decode(tag_b64)
    except:
        log_event(client_ip, offset_id, "invalid_encoding")
        return jsonify({"error": "invalid_encoding"}), 400)

    # Decrypt and verify
    try:
        offset_value = decrypt_offset(ciphertext, iv, tag, session_key)
        expected_value = EXPECTED_OFFSETS.get(offset_id)
        if offset_value != expected_value:
            log_event(client_ip, offset_id, "tampering_detected")
            return jsonify({"error": "invalid_offset"}), 403)
        log_event(client_ip, offset_id, "success")
        return jsonify({"status": "success"}), 200
    except Exception:
        log_event(client_ip, offset_id, "decryption_failed")
        return jsonify({"error": "decryption_failed"}), 400)

if __name__ == '__main__':
    init_db()
    app.run(ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=443)
```

---

#### README.md`
Updated with detailed setup, security hardening, and Unreal Engine integration steps.

<xaiArtifact artifact_id="611ef584-a08f-4611-b29a-a4edc4a7c875" artifact_version_id="a9c7b725-f7c7-48ae-a560-68a4cdffab57" title="README.md" contentType="text/markdown">
# Anti-Cheat System with Secure Offset Verification

This anti-cheat system protects Unreal Engine games by verifying offsets on a server using AES-256-GCM and securing communication with TLS 1.3. A kernel driver handles local anti-tampering.

## System Overview
- **AntiCheatDriver.cpp**:
  - Checks for debuggers and logs tampering attempts.
  - Supports IOCTLs for integrity checks and log retrieval.
- **AntiCheatUser.cpp**:
  - Performs ECDH key exchange for dynamic session keys.
  - Encrypts AES-256-GCM encrypts offsets with AES-GCM, sends to server via HTTPS.
  - Uses secure nonces and timestamps.
- **AntiCheatCommon.h**:
  - Defines IOCTLs for driver communication.
- **AntiCheatServer.py**:
  - Verifies Flask server verifies encrypted offsets.
  - Supports ECDH, API key authentication, nonce window, and SQLite logging.

## Security Features
- **TLS 1.3**: Encrypts all network traffic.
- **AES-256-GCM**: Protects offsets with authenticated encryption.
- **ECDH**: Derives session keys dynamically.
- **Nonces/Timestamps**: Prevents replay attacks.
- **API Keys**: Authenticates clients.
- **Kernel Driver**: Detects local tampering.

## Security Notes
- **TLS**: Use a CA-issued certificate in production (not `cert.pem`/`key.pem`).
- **API Keys**: Store securely, rotate regularly.
- **Session Keys**: ECDH ensures unique keys per session.
- **Nonce Window**: Limits memory usage for replay protection.
- **Obfuscation**: Apply to client binary to prevent reverse-engineering.
- **Server**: Harden with nginx, HSTS, and rate-limiting.

## Build Instructions
- **Driver**:
  - Install WDK.
  - Build `AntiCheatDriver.cpp` as `.sys` with Visual Studio.
- **User-Mode**:
  - Compile `AntiCheatUser.cpp` with MSVC, linking `winhttp.lib`, `bcrypt.lib`.
  - Replace `yourserver.com` and `your_api_key`.
- **Server**:
  - Install Python 3, Flask, cryptography (`pip install flask cryptography`).
  - Create SQLite DB:
    ```bash
    python -c "from AntiCheatServer import init_db; init_db()"
    ```
  - Generate TLS certificate:
    ```bash
    openssl req -x509 -newkey rsa:2048 -nodes -out cert.pem -keyout key.pem -days 365
    ```
  - Run server:
    ```bash
    python AntiCheatServer.py
    ```

## Deployment
- **Driver**: Load with test signing or a driver loader.
- **User-Mode**: Run `AntiCheatUser.exe` alongside the game.
- **Server**:
  - Deploy behind nginx:
    ```nginx
    server {
        listen 443 ssl http2;
        server_name yourserver.com;
        ssl_certificate /etc/letsencrypt/cert.pem;
        ssl_certificate_key /etc/letsencrypt/key.pem;
        add_header Strict-Transport-Security "max-age=31536000";
        location / {
            proxy_pass http://127.0.0.1:5000;
        }
    }
    ```
  - Enable rate-limiting with Flask-Limiter.

## Unreal Engine Integration
- Hook into `PlayerController` or `GameInstance`:
  ```cpp
  void AMyPlayerController::Tick(float DeltaTime) {
      Super::Tick(DeltaTime);
      SendOffsetToServer("player_health", *(ULONG*)HealthPtr);
  }
  ```
- Update `EXPECTED_OFFSETS` in `AntiCheatServer.py`.
- Use Unreal’s `HttpModule` instead of WinHTTP for native integration.

## Next Steps
- Obfuscate client binary with Obfuscator-LLVM.
- Add server-side ban logic for repeated tampering.
- Implement fallback local verification in driver.
- Monitor logs in `logs.db` for anomalies.