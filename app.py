from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins=["https://kanban-frontend-delta.vercel.app"], supports_credentials=True)

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    password = data.get("password")
    return jsonify({
        "message": "User registered successfully!",
        "name": name,
        "email": email
    }), 200
