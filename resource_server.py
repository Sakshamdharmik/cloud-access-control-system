from flask import Flask, request, jsonify
import json
from datetime import datetime
import hashlib
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

from db_config import get_db_connection

app = Flask(__name__)

# Load public key of the cloud server
with open("keys/public.pem", "rb") as f:
    public_key = RSA.import_key(f.read())

@app.route('/access-resource', methods=['POST'])
def access_resource():
    data = request.json
    token = data['token']

    try:
        token_str, sig_hex = token.split("::")
        signature = bytes.fromhex(sig_hex)

        hash_obj = SHA256.new(token_str.encode())
        pkcs1_15.new(public_key).verify(hash_obj, signature)

        token_data = json.loads(token_str)

        expiry = datetime.strptime(token_data['expiry'], '%Y-%m-%d %H:%M:%S')
        if datetime.now() > expiry:
            return jsonify({"error": "Token expired"}), 401

        # Check if revoked
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM revocation_list WHERE token_hash = %s", (token_hash,))
        count = cursor.fetchone()[0]

        if count > 0:
            return jsonify({"error": "Token revoked"}), 401

        return jsonify({
            "message": "Access granted",
            "rights": token_data["rights"],
            "object_id": token_data["object_id"]
        })

    except Exception as e:
        return jsonify({"error": "Invalid token", "details": str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True, port=6000)
