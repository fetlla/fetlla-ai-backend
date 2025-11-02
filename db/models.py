import uuid
from datetime import datetime
from sqlalchemy import ForeignKey, DateTime, func, event, Text, JSON, String, Uuid
from sqlalchemy.orm import Mapped, relationship, DeclarativeBase, Session
from sqlalchemy.orm import mapped_column
from typing import Optional

class Base(DeclarativeBase):
    pass


class Users(Base):
    __tablename__ = 'users'

    id:Mapped[int] = mapped_column(primary_key=True,index=True)
    username:Mapped[str]
    first_name:Mapped[str]
    last_name:Mapped[str]
    password:Mapped[str]
    role:Mapped[str]
    two_factor:Mapped["TwoFactor"] = relationship(back_populates="user", single_parent=True,cascade="all, delete-orphan",
        uselist=False )
    chats:Mapped[list["Chat"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class TwoFactor(Base):
    __tablename__ = 'two_factor'

    id:Mapped[int] = mapped_column(primary_key=True,index=True)
    user_id:Mapped[int] = mapped_column(ForeignKey("users.id"))
    user:Mapped["Users"] = relationship(back_populates="two_factor", single_parent=True)
    user_hash:Mapped[str]
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(),onupdate=func.now())


class Chat(Base):
    __tablename__ = "chats"
    
    id:Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4, index=True)
    user_id:Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    title:Mapped[str] = mapped_column(String, nullable=False)
    created_at:Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at:Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), onupdate=func.now())
    
    user:Mapped["Users"] = relationship(back_populates="chats")
    messages:Mapped[list["ChatMessage"]] = relationship(back_populates="chat", cascade="all, delete-orphan")


class ChatMessage(Base):
    __tablename__ = "chat_messages"
    
    id:Mapped[int] = mapped_column(primary_key=True, index=True)
    chat_id:Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("chats.id"), nullable=False)
    role:Mapped[str] = mapped_column(String, nullable=False)  # "human" or "ai"
    content:Mapped[str] = mapped_column(Text, nullable=False)
    message_metadata:Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at:Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    
    chat:Mapped["Chat"] = relationship(back_populates="messages")



@event.listens_for(Session, "after_flush")
def create_two_factor(session, flush_context):
    for instance in session.new:
        if isinstance(instance, Users):
            two_factor = TwoFactor(user=instance, user_hash=uuid.uuid4().hex)
            session.add(two_factor)


