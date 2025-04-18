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


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    email = data.get('email')
    password = data.get('password')

    if not email or not password: 
        return jsonify({"error": "Missing email or password"}), 400
    
    #Find user in db
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "Invalid cerdentials"}), 401
    
    #check pw in bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        return jsonify({"error": "Invalid credentials"}), 401
    
    #Return JWT if credentials are valid
    access_token = create_access_token(identity=user.id)
    return jsonify({"access_token": access_token}), 200