# apps/dbmodels.py
import enum
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from apps.extensions import db

class UserType(enum.Enum):  # 사용자 구분(순서 중요)
    USER = 'user'
    EXPERT = 'expert'
    ADMIN = 'admin'

class UserLogType(enum.Enum):  # 사용자 로그 구분
    ACCOUNT_STATUS_CHANGE = "계정상태변경"
    USER_ROLE_CHANGE = "사용자역할변경"
    USER_INFO_MODIFY = "사용자정보수정"
    USER_ERASE = "사용자삭제"
    USER_CREATE = "사용자생성"

class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, index=True)
    email = db.Column(db.String, unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    user_type = db.Column(db.Enum(UserType), nullable=False, default=UserType.USER)
    is_active = db.Column(db.Boolean, default=True)
    is_deleted = db.Column(db.Boolean, default=False)
    usage_count = db.Column(db.Integer, default=0)
    daily_limit = db.Column(db.Integer, default=1000)
    monthly_limit = db.Column(db.Integer, default=5000)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # [수정] backref 대신 back_populates를 사용하여 양방향 관계를 명시적으로 설정
    action_logs = db.relationship('Log', foreign_keys='Log.user_id', back_populates='actor', lazy='dynamic')
    targeted_logs = db.relationship('Log', foreign_keys='Log.target_user_id', back_populates='target_user', lazy='dynamic')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        if self.password_hash is None:
            return False
        return check_password_hash(self.password_hash, password)

    def is_admin(self):
        return self.user_type == UserType.ADMIN

    def is_expert(self):
        return self.user_type == UserType.EXPERT

    def is_user(self):
        return self.user_type == UserType.USER

    # [수정] 이메일 중복 체크 로직 수정
    def is_duplicate_email(self):
        query = User.query.filter_by(email=self.email)
        # 만약 self.id가 존재한다면 (즉, 이미 데이터베이스에 저장된 사용자라면)
        # 자기 자신은 중복 체크에서 제외해야 함
        if self.id:
            query = query.filter(User.id != self.id)
        return query.first() is not None

    def soft_delete(self):
        """
        사용자를 soft-delete 처리합니다.
        실제 데이터를 삭제하는 대신, is_deleted 플래그를 True로,
        is_active 플래그를 False로 설정합니다.
        """
        self.is_deleted = True
        self.is_active = False

    def __repr__(self):
        return f'<User {self.username}>'

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    
    # 외래 키 정의는 그대로 유지
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, comment="행위를 수행한 사용자 ID")
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, comment="행위의 대상이 된 사용자 ID")
    
    # [수정] backref 대신 back_populates를 사용하고, 상대편 모델의 속성 이름을 정확히 지정
    actor = db.relationship('User', foreign_keys=[user_id], back_populates='action_logs')
    target_user = db.relationship('User', foreign_keys=[target_user_id], back_populates='targeted_logs')
    
    endpoint = db.Column(db.String(120), nullable=False)
    log_title = db.Column(db.String(50), nullable=False)
    log_summary = db.Column(db.Text)
    
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    
    remote_addr = db.Column(db.String(45))
    response_status_code = db.Column(db.Integer)

    def __repr__(self) -> str:
        return f"<Log(user_id={self.user_id}, target_user_id={self.target_user_id}, log_title='{self.log_title}')>"

