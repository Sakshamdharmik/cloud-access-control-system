from flask import Flask, request, jsonify
from datetime import datetime, timedelta
import hashlib
import json
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from db_config import get_db_connection

app = Flask(__name__)

# Load Private Key
with open("keys/private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# 1. Register User
@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data['username']
    password = data['password']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
    conn.commit()

    return jsonify({"message": "User registered successfully."})

# 2. Add Object
@app.route('/add-object', methods=['POST'])
def add_object():
    data = request.json
    name = data['name']

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO objects (name) VALUES (%s)", (name,))
    conn.commit()

    return jsonify({"message": "Object added successfully."})

# 3. Generate Capability Token
@app.route('/generate-token', methods=['POST'])
def generate_token():
    data = request.json
    username = data['username']
    object_name = data['object']
    rights = data['rights']  # e.g., "read,write"

    expiry = datetime.now() + timedelta(minutes=30)
    expiry_str = expiry.strftime('%Y-%m-%d %H:%M:%S')

    nonce = hashlib.sha256(str(datetime.now()).encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    subject_id = cursor.fetchone()[0]

    cursor.execute("SELECT id FROM objects WHERE name = %s", (object_name,))
    object_id = cursor.fetchone()[0]

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

    cursor.execute("INSERT INTO capabilities (subject_id, object_id, rights, expiry, nonce, token) VALUES (%s, %s, %s, %s, %s, %s)",
                   (subject_id, object_id, rights, expiry_str, nonce, signed_token))
    conn.commit()

    return jsonify({"token": signed_token})

# 4. Revoke Token
@app.route('/revoke-token', methods=['POST'])
def revoke_token():
    data = request.json
    token = data['token']

    token_hash = hashlib.sha256(token.encode()).hexdigest()

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO revocation_list (token_hash) VALUES (%s)", (token_hash,))
    conn.commit()

    return jsonify({"message": "Token revoked successfully."})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
