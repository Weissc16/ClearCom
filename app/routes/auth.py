from flask import Blueprint, request, jsonify, current_app 
from app import db, limiter
from app.models import *
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_limiter.util import get_remote_address
import bcrypt
import re

auth_bp = Blueprint('auth', __name__)



@auth_bp.route('/ping', methods=['GET'])
def ping():
    return jsonify({"message": "Auth route working!"})


def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) and len(email) <= 100


def is_strong_password(password):
    return(
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password)
    )

@auth_bp.route('/register', methods=['POST'])
@limiter.limit("5 per minute", key_func=get_remote_address)
def register():
    data = request.get_json()  # 📥 Parse JSON body
    if not data:
        return jsonify({"error": "No data provided"}), 400  # ✅ Add this safeguard
    
    #Capture IP address
    ip_address = request.remote_addr
    print(f"Registration attempt from IP: {ip_address}")


    email = data.get('email')
    password = data.get('password')

    #Valid email format
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format"}), 400

    #Validate password strength
    if not is_strong_password(password):
        return jsonify({"error": "Password must be at least 8 characters long, and include uppercase, lowercase, and a number."}), 400

    #Check for existing user
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 409

    #hash and store password
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

    new_user = User(email=email, password_hash=hashed_password.decode('utf-8'))
    db.session.add(new_user)
    db.session.commit()

    #Issue JWT token
    access_token = create_access_token(identity=str(new_user.id))

    return jsonify({"access_token": access_token}), 201  



@auth_bp.route('/login', methods=['POST'])
@limiter.limit("5 per minute", key_func=get_remote_address)
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password: 
        return jsonify({"error": "Missing email or password"}), 400
    
    #Find user in db, log failed attempts
    user = User.query.filter_by(email=email).first()
    if not user:
        current_app.logger.warning(f"Failed login attempt for non-existent user: {email}")
        return jsonify({"error": "Invalid cerdentials"}), 401
    
    #check pw in bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
        current_app.logger.warning(f"Failed login attempt for user: {email}")
        return jsonify({"error": "Invalid credentials"}), 401
    
    #Return JWT if credentials are valid
    access_token = create_access_token(identity=str(user.id))
    current_app.logger.info(f"User logged in: {email}")

    return jsonify({"access_token": access_token}), 200



@auth_bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    user_id = get_jwt_identity() #Get user id from JWT
    return jsonify({"message": f"Welcome user {user_id}!"}), 200



@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity() #Get user ID from JWT
    user = User.query.get(user_id) #Loot up the user in the database

    if not user:
        return jsonify({"error": "User not found"}), 404
    
    return jsonify({
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at
    }), 200



@auth_bp.route('/chatrooms', methods=['POST'])
@jwt_required()
def create_chatroom():
    data = request.get_json()
    name = data.get('name')

    if not name:
        return jsonify({"error": "Chatroom name is required"}), 400
    
    user_id = get_jwt_identity()

    new_chatroom = Chatroom(name=name, creator_id=user_id)

    db.session.add(new_chatroom)
    db.session.commit()

    chatroom_member = ChatroomMember(chatroom_id=new_chatroom.id, user_id=user_id)
    db.session.add(chatroom_member)
    db.session.commit()

    return jsonify({
        "message": "Chatroom created successfully!",
        "chatroom": {
            "id": new_chatroom.id,
            "name": new_chatroom.name,
            "creator_id": new_chatroom.creator_id,
            "created_at": new_chatroom.created_at
        }
    }), 201



@auth_bp.route('/my_chatrooms', methods=['GET'])
@jwt_required()
def my_chatrooms():
    user_id = get_jwt_identity()

    chatroom_memberships = ChatroomMember.query.filter_by(user_id=user_id).all()
    chatrooms = []

    for membership in chatroom_memberships:
        chatroom = membership.chatroom

        # Get all members of the chatroom
        members = [
            {
                "id": member.user.id,
                "email": member.user.email
            }
            for member in chatroom.members
        ]

        chatrooms.append({
            "id": chatroom.id,
            "name": chatroom.name,
            "creator_id": chatroom.creator_id,
            "created_at": chatroom.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            "members": members
        })

    return jsonify({"chatrooms": chatrooms})


        
@auth_bp.route('/send_message', methods=['POST'])
@jwt_required()
def send_message():
    data = request.get_json()
    user_id = get_jwt_identity()
    chatroom_id = data.get("chatroom_id")
    content = data.get("content")

    if not chatroom_id or not content:
        return jsonify({"error": "chatroom_id and notent are required"}), 400
    
    #Verify user is a member of the chatroom
    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this chatroom"}), 403
    
    message = Message(chatroom_id=chatroom_id, sender_id=user_id, content=content)
    db.session.add(message)
    db.session.commit()

    return jsonify({"messgae": "Message sent successfully"})



@auth_bp.route('chatroom/<int:chatroom_id>/messages', methods=['GET'])
@jwt_required()
def get_chatroom_messages(chatroom_id):
    user_id = get_jwt_identity()

    #Ensure user is part of the chatroom
    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    if not membership:
        return jsonify({"error": "Access denied to this chatroom"}), 403
    
    messages = Message.query.filter_by(chatroom_id=chatroom_id).order_by(Message.timestamt.asc()).all()

    return jsonify({
        "chatroom_id": chatroom_id,
        "messages": [
            {
                "sender": msg.sender.email,
                "content": msg.content,
                "timestamp": msg.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            }
            for msg in messages
        ]
    })



@auth_bp.route('/delete_message/<int:message_id>', methods=['DELETE'])
@jwt_required()
def delete_messgae(message_id):
    user_id = get_jwt_identity()

    #find the message
    message = Message.query.get(message_id)
    if not message:
        return jsonify({"error": "Message not found"}), 404
    
    #Make sure the requester is the sender
    if message.sender_id != user_id:
        return jsonify({"error": "You are not authorized to delete this message"}), 403
    
    #delete the message
    db.session.delete(message)
    db.session.commit()

    return jsonify({"message": "Message deleted successfully"}), 200