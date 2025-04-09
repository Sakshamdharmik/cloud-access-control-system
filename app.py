from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import hashlib
import json
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from db_config import get_db_connection

app = Flask(__name__)

# Load RSA Private Key
with open("keys/private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# 🔐 Secure Password Hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ✅ 1. Register User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    hashed = hash_password(password)
    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed))
    conn.commit()

    return jsonify({"message": "User registered successfully."})

# ✅ 2. Add Object
@app.route('/add-object', methods=['POST'])
def add_object():
    data = request.json
    name = data.get('name')

    if not name:
        return jsonify({"error": "Object name is required."}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO objects (name) VALUES (%s)", (name,))
    conn.commit()

    return jsonify({"message": "Object added successfully."})

# ✅ 3. Generate Capability Token
@app.route('/generate-token', methods=['POST'])
def generate_token():
    data = request.json
    username = data.get('username')
    object_name = data.get('object')
    rights = data.get('rights')

    if not all([username, object_name, rights]):
        return jsonify({"error": "username, object, and rights are required."}), 400

    expiry = datetime.now() + timedelta(minutes=30)
    expiry_str = expiry.strftime('%Y-%m-%d %H:%M:%S')
    nonce = hashlib.sha256(str(datetime.now()).encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    user_row = cursor.fetchone()
    if not user_row:
        return jsonify({"error": "User not found."}), 404
    subject_id = user_row[0]

    cursor.execute("SELECT id FROM objects WHERE name = %s", (object_name,))
    obj_row = cursor.fetchone()
    if not obj_row:
        return jsonify({"error": "Object not found."}), 404
    object_id = obj_row[0]

    token_data = {
        "subject_id": subject_id,
        "object_id": object_id,
        "rights": rights,
        "expiry": expiry_str,
        "nonce": nonce
    }

    token_str = json.dumps(token_data)
    hash_obj = SHA256.new(token_str.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    signed_token = token_str + "::" + signature.hex()

    cursor.execute(
        "INSERT INTO tokens (user_id, object_id, action, token, expiry, is_revoked) VALUES (%s, %s, %s, %s, %s, %s)",
        (subject_id, object_id, rights, signed_token, expiry_str, False)
    )
    conn.commit()

    return jsonify({"token": signed_token})

# ✅ 4. Revoke Token
@app.route('/revoke-token', methods=['POST'])
def revoke_token():
    data = request.json
    token = data.get('token')
    if not token:
        return jsonify({"error": "Token is required."}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO revocation_list (token_hash) VALUES (%s)", (token_hash,))
    conn.commit()

    return jsonify({"message": "Token revoked successfully."})

# ✅ Root check
@app.route('/')
def home():
    return "✅ Capability-Based Access Control API is live!"

# ✅ Render-friendly startup
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
