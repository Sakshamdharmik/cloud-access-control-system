from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime, timedelta
from dotenv import load_dotenv
import hashlib
import json
import os
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# Load environment variables
load_dotenv()

# Flask app
app = Flask(__name__)

# MongoDB client
client = MongoClient(os.getenv("MONGO_URI"))
db = client["cap_db"]

# Load RSA Private Key
with open("keys/private.pem", "rb") as f:
    private_key = RSA.import_key(f.read())

# 🔐 Password hashing
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# ✅ 1. Register User
@app.route("/register", methods=["POST"])
def register_user():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    hashed_pw = hash_password(password)
    db.users.insert_one({"username": username, "password": hashed_pw})
    return jsonify({"message": "User registered successfully"}), 201

# ✅ 2. Add Object
@app.route("/add-object", methods=["POST"])
def add_object():
    data = request.get_json()
    name = data.get("name")

    if not name:
        return jsonify({"error": "Object name required"}), 400

    db.objects.insert_one({"name": name})
    return jsonify({"message": "Object added successfully"}), 201

# ✅ 3. Generate Token
@app.route("/generate-token", methods=["POST"])
def generate_token():
    data = request.get_json()
    username = data.get("username")
    object_name = data.get("object")
    rights = data.get("rights")

    if not all([username, object_name, rights]):
        return jsonify({"error": "username, object, and rights are required"}), 400

    user = db.users.find_one({"username": username})
    obj = db.objects.find_one({"name": object_name})

    if not user or not obj:
        return jsonify({"error": "User or Object not found"}), 404

    expiry = datetime.utcnow() + timedelta(minutes=30)
    expiry_str = expiry.strftime('%Y-%m-%d %H:%M:%S')
    nonce = hashlib.sha256(str(datetime.utcnow()).encode()).hexdigest()

    token_data = {
        "subject_id": str(user["_id"]),
        "object_id": str(obj["_id"]),
        "rights": rights,
        "expiry": expiry_str,
        "nonce": nonce
    }

    token_str = json.dumps(token_data)
    hash_obj = SHA256.new(token_str.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    signed_token = token_str + "::" + signature.hex()

    db.tokens.insert_one({
        "user_id": str(user["_id"]),
        "object_id": str(obj["_id"]),
        "rights": rights,
        "token": signed_token,
        "expiry": expiry,
        "is_revoked": False
    })

    return jsonify({"token": signed_token}), 200

# ✅ 4. Revoke Token
@app.route("/revoke-token", methods=["POST"])
def revoke_token():
    data = request.get_json()
    token = data.get("token")
    if not token:
        return jsonify({"error": "Token is required"}), 400

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.revocation_list.insert_one({"token_hash": token_hash})
    return jsonify({"message": "Token revoked successfully"}), 200

# ✅ Root Check
@app.route("/")
def home():
    return "✅ MongoDB-based Capability Access Control API is running!"

# ✅ Render-friendly start
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
