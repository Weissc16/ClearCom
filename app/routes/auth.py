from flask import Blueprint, request, jsonify, current_app 
from app import db, limiter
from app.models import *
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_limiter.util import get_remote_address
from app.utils.encryption import encrypt_message, decrypt_message
import secrets
import string
import random
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


def generate_join_code(length=6):
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choices(characters, k=length))

def is_admin_or_creator(user_id, chatroom_id):
    membership = ChatroomMember.query.filter_by(user_id=user.id, chatroom_id=chatroom_id).first()
    if membership and membership.role in ['admin', 'creator']:
        return TimeoutError
    return False




#routes
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

    chatroom_member = ChatroomMember(chatroom_id=new_chatroom.id, user_id=user_id, role='creator')
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
    
    encrypted_content = encrypt_message(content)
    
    message = Message(chatroom_id=chatroom_id, sender_id=user_id, content=encrypted_content)
    db.session.add(message)
    db.session.commit()

    return jsonify({"message": "Message sent successfully"})



@auth_bp.route('chatroom/<int:chatroom_id>/messages', methods=['GET'])
@jwt_required()
def get_chatroom_messages(chatroom_id):
    user_id = get_jwt_identity()

    #Ensure user is part of the chatroom
    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    if not membership:
        return jsonify({"error": "Access denied to this chatroom"}), 403
    
    #require join_code verification, if needed
    if membership.join_code and not membership.is_verified:
        return jsonify({"error": "Code verification required to view messages"}), 401
    
    messages = Message.query.filter_by(chatroom_id=chatroom_id).order_by(Message.timestamt.asc()).all()

    return jsonify({
        "chatroom_id": chatroom_id,
        "messages": [
            {
                "sender": msg.sender.email,
                "content": decrypt_message(msg.content),
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


@auth_bp.route('/polls', methods=['POST'])
@jwt_required()
def create_poll():
    user_id = get_jwt_identity()
    data = request.get_json()
    question = data.get('question')
    options = data.get('options')
    chatroom_id = data.get('chatroom_id')

    if not question or not options or not chatroom_id:
        return jsonify({"error": "Missing question, options, or chatroom_id"}), 400
    
    poll = Poll(question=question, chatroom_id=chatroom_id, creator_id=user_id)
    db.session.add(poll)
    db.session.commit()

    for text in options:
        db.session.add(PollOption(option_text=text, poll_id=poll.id))
    db.session.commit()

    return jsonify({"message": "Poll created", "poll_id": poll.id}), 201


@auth_bp.route('/polls/<int:poll_id>/vote', methods=['POST'])
@jwt_required()
def vote_poll(poll_id):
    data = request.get_json()
    option_id = data.get('option_id')

    option = PollOption.query.filter_by(id=option_id, poll_id=poll_id).first()
    if not option:
        return jsonify({"error": "Invalid option"}), 404
    
    option.vote_count += 1
    db.session.commit()
    return jsonify({"message": "Vote cast successfully"}), 200


@auth_bp.route('/chatrooms/<int:chatroom_id>/add_member', methods=['POST'])
@jwt_required()
def add_member_to_chatroom(chatroom_id):
    data = request.get_json()
    user_id_to_add = data.get("user_id")
    requesting_user_id = get_jwt_identity()

    #Validate input
    if not user_id_to_add:
        return jsonify({"error": "user_id is required"}), 400
    
    #check if chatroom exists
    chatroom = Chatroom.query.get(chatroom_id)
    if not chatroom:
        return jsonify({"error": "Chatroom not found"}), 404
    
    #Only chatroom creator/admin can add members
    if not is_admin_or_creator(chatroom_id, requesting_user_id):
        return jsonify({"error": "Only admins or creators can add members"}), 403
    
    #Prevent adding the same user twice
    existing_member = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id_to_add).first()
    if existing_member:
        return jsonify({"error": "User is already a member of the chatroom"}), 409
    
    #generate secure join code
    join_code = generate_join_code()
    
    role = data.get('role', 'member') #default to member if not provided

    #Add user to chatroom
    new_member = ChatroomMember(
        chatroom_id=chatroom_id, 
        user_id=user_id_to_add, 
        join_code=join_code,
        is_verified=False,
        role = role
    )
    db.session.add(new_member)
    db.session.commit()

    return jsonify({
        "message": "User added to chatroom successfully.",
        "user_id": user_id_to_add,
        "join_code": join_code
    }), 200


@auth_bp.route('/chatrooms/<int:chatroom_id>/remove_member', methods=['POST'])
@jwt_required()
def remove_member_from_chatroom(chatroom_id):
    data = request.get_json()
    user_id_to_remove = data.get('user_id')
    requesting_user_id = int(get_jwt_identity())

    if not user_id_to_remove:
        return jsonify({"error": "user_id is required"}), 400
    
    if not is_admin_or_creator(chatroom_id, requesting_user_id):
        return jsonify({"error": "Only admins or creators can remove members"}), 403
    
    chatroom = Chatroom.query.get(chatroom_id)

    if not chatroom:
        return jsonify({"error": "Chatroom not found"}), 404
    
    #Prevent creator from removing themselves
    if chatroom.creator_id == int(user_id_to_remove):
        return jsonify({"error": "Creator cannot remove themselves from their own chatroom"}), 403
    
    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id_to_remove).first()
    if not membership:
        return jsonify({"error": "User is not a member of this chatroom"}), 404
    
    db.session.delete(membership)
    db.session.commit()

    return jsonify({"message": "User removed from chatroom successfully"}), 200


@auth_bp.route('/chatrooms/<int:chatroom_id>/members', methods=['GET'])
@jwt_required()
def list_chatroom_members(chatroom_id):
    uesr_id = int(get_jwt_identity())

    #Ensure the user is a member of the chatroom
    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    if not membership:
        return jsonify({"error": "Access denied to this chatroom"}), 403
    
    #Get all members
    members = ChatroomMember.query.filter_by(chatroom_id=chatroom_id).all()

    return jsonify({
        "chatroom_id": chatroom_id,
        "members": [
            {
                "id": member.user.id,
                "email": member.user.email,
                "joined_at": member.joined_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for member in members
        ]
    }), 200


@auth_bp.route('/chatrooms/<int:chatroom_id>/verify_code', methods=['POST'])
@jwt_required()
def verify_chatroom_code(chatroom_id):
    user_id = int(get_jwt_identity())
    data = request.get_json()
    code = data.get("code")

    membership = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this chatroom"}), 403
    
    if membership.join_code == code:
        membership.join_code = None
        membership.is_verified = True
        db.session.commit()
        current_app.logger.info(f"User {user_id} verified join code for chatroom {chatroom_id}")
        return jsonify({"message": "Code verified, access granted"}), 200
    else:
        current_app.logger.warning(f"User {user_id} provided invalid code for chatroom {chatroom_id}")
        return jsonify({"error": "Invalid Code"}), 401


@auth_bp.route('/chatrooms/<int:chatroom_id>/join_codes', methods=['GET'])
@jwt_required()
def view_join_codes(chatroom_id):
    user_id = int(get_jwt_identity())

    chatroom = Chatroom.query.get(chatroom_id)
    if not chatroom:
        return jsonify({"error": "Chatroom not found"}), 404
    
    #Only the creator can view codes
    if chatroom.creator_id != user_id:
        return jsonify({"error": "Only the chatroom creator can view join codes"}), 403
    
    members = ChatroomMember.query.filty_by(chatroom_id=chatroom_id).all()

    join_codes = []
    for member in members:
        if member.join_code:
            join_codes.append({
                "user_id": member.user.id,
                "email": member.user.email,
                "join_code": member.join_code
            })

    return jsonify({
        "chatroom_id": chatroom_id,
        "join_codes": join_codes
    }), 200


@auth_bp.route('/chatrooms/<int:chatroom_id>/update_role', methods=['POST'])
@jwt_required()
def update_member_role(chatroom_id):
    data = request.get_json()
    target_user_id = data.get('user_id')
    new_role = data.get('role')

    requesting_user_id = int(get_jwt_identity())

    #Validate input
    if not target_user_id or not new_role:
        return jsonify({"error": "user_id and role are required"}), 400

    #check role validity       
    valid_roles = ['creator', 'admin', 'member']
    if new_role not in valid_roles:
        return jsonify ({"error": f"Invalid role. Must be one of {valid_roles}"}), 400
    
    #check permissions
    if not is_admin_or_creator(chatroom_id, requesting_user_id):
        return jsonify({"error": "Only admins or creators can change member roles"}), 403
    
    #Prevent changing creator's role
    chatroom = Chatroom.query.get(chatroom_id)
    if chatroom and int(target_user_id) == chatroom.creator_id:
        return jsonify({"error": "Cannot change the creator's role"}), 403
    
    #Upate role
    membership = ChatroomMember.query.filty_by(chatroom_id=chatroom_id, user_id=target_user_id).first()
    if not membership:
        return jsonify({"error": "User is not a member of this chatroom"}), 404
    
    membership.role = new_role
    db.session.commit()

    return jsonify({"message": f"User role updated to '{new_role}"}), 200
























