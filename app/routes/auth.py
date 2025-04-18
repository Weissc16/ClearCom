from flask import Blueprint, request, jsonify  # ✅ make sure 'request' is included
from app import db
from app.models import User
from flask_jwt_extended import create_access_token
import bcrypt

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/ping', methods=['GET'])
def ping():
    return jsonify({"message": "Auth route working!"})

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()  # 📥 Parse JSON body
    if not data:
        return jsonify({"error": "No data provided"}), 400  # ✅ Add this safeguard

    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"error": "Missing email or password"}), 400  # ✅ Validate input

    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 409

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    new_user = User(email=email, password_hash=hashed_password.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=new_user.id)
    return jsonify({"access_token": access_token}), 201  # ✅ THIS is your final response
