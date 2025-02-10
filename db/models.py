import uuid
from datetime import datetime
from sqlalchemy import ForeignKey, DateTime, func, event
from sqlalchemy.orm import Mapped, relationship, DeclarativeBase, Session
from sqlalchemy.orm import mapped_column

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


class TwoFactor(Base):
    __tablename__ = 'two_factor'

    id:Mapped[int] = mapped_column(primary_key=True,index=True)
    user_id:Mapped[int] = mapped_column(ForeignKey("users.id"))
    user:Mapped["Users"] = relationship(back_populates="two_factor", single_parent=True)
    user_hash:Mapped[str]
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(),onupdate=func.now())



@event.listens_for(Session, "after_flush")
def create_two_factor(session, flush_context):
    for instance in session.new:
        if isinstance(instance, Users):
            two_factor = TwoFactor(user=instance, user_hash=uuid.uuid4().hex)
            session.add(two_factor)


