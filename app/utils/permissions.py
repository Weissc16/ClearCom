from app.models import ChatroomMember

def is_admin(chatroom_id, user_id):
    member = ChatroomMember.query.filter_by(chatroom_id=chatroom_id, user_id=user_id).first()
    return member is not None and member.role == 'admin'
