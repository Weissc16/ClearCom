from app.extensions import db
from datetime import datetime

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<User {self.email}>"
    
    
class Mission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    classification = db.Column(db.String(50), default="Confidential")
    status = db.Column(db.String(50), default="Planned")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    chatrooms = db.relationship("Chatroom", backref="mission", lazy=True)


class Chatroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    mission_id = db.Column(db.Integer, db.ForeignKey('mission.id', name='fk_chatroom_mission_id'), nullable=True)

    def __repr__(self):
        return f"<Chatroom {self.name}>"
    

class ChatroomMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    join_code = db.Column(db.String(10), nullable=True) #Encrypted join code
    is_verified = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='member') #roles: creator, admin, member
    mission_id = db.Column(db.Integer, db.ForeignKey('mission.id'), nullable=True)
    
    missiono = db.relationship('Mission', backref='mission_memberships')
    chatroom = db.relationship('Chatroom', backref=db.backref('members', lazy=True))
    user = db.relationship('User', backref=db.backref('chatrooms', lazy=True))


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    chatroom = db.relationship('Chatroom', backref=db.backref('messages', lazy=True))
    sender = db.relationship('User')


class Poll(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    chatroom_id = db.Column(db.Integer, db.ForeignKey('chatroom.id'), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class PollOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option_text = db.Column(db.String(255), nullable=False)
    poll_id = db.Column(db.Integer, db.ForeignKey('poll.id'), nullable=False)
    vote_count = db.Column(db.Integer, default=0)


