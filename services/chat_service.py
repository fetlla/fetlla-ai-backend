from sqlalchemy.orm import Session
from db.models import Chat, ChatMessage
from datetime import datetime
from typing import List, Optional
from uuid import UUID


class ChatService:
    """Service class for managing chats and messages"""
    
    @staticmethod
    def create_chat(user_id: int, title: str, db: Session) -> Chat:
        """Create new chat for a user"""
        chat = Chat(user_id=user_id, title=title)
        db.add(chat)
        db.commit()
        db.refresh(chat)
        return chat
    
    @staticmethod
    def get_user_chats(user_id: int, db: Session) -> List[Chat]:
        """Get all chats for a user, ordered by most recently updated"""
        return db.query(Chat).filter(
            Chat.user_id == user_id
        ).order_by(Chat.updated_at.desc()).all()
    
    @staticmethod
    def get_chat_by_id(chat_id: UUID, db: Session) -> Optional[Chat]:
        """Get a specific chat by ID"""
        return db.query(Chat).filter(Chat.id == chat_id).first()
    
    @staticmethod
    def get_chat_messages(chat_id: UUID, db: Session, limit: Optional[int] = None) -> List[ChatMessage]:
        """Get all messages in a chat, ordered chronologically"""
        query = db.query(ChatMessage).filter(
            ChatMessage.chat_id == chat_id
        ).order_by(ChatMessage.created_at)
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    @staticmethod
    def add_message(
        chat_id: UUID,
        role: str,
        content: str,
        metadata: dict,
        db: Session
    ) -> ChatMessage:
        """Add a message to a chat"""
        message = ChatMessage(
            chat_id=chat_id,
            role=role,
            content=content,
            message_metadata=metadata
        )
        db.add(message)
        
        # Update chat's updated_at timestamp
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if chat:
            chat.updated_at = datetime.utcnow()
        
        db.commit()
        db.refresh(message)
        return message
    
    @staticmethod
    def update_chat_title(chat_id: UUID, title: str, db: Session) -> Optional[Chat]:
        """Update chat title"""
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if chat:
            chat.title = title
            chat.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(chat)
        return chat
    
    @staticmethod
    def delete_chat(chat_id: UUID, db: Session) -> bool:
        """Delete chat and all its messages (cascade)"""
        chat = db.query(Chat).filter(Chat.id == chat_id).first()
        if chat:
            db.delete(chat)
            db.commit()
            return True
        return False
    
    @staticmethod
    def get_message_count(chat_id: UUID, db: Session) -> int:
        """Get count of messages in a chat"""
        return db.query(ChatMessage).filter(ChatMessage.chat_id == chat_id).count()
