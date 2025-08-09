# apps/dbmodels.py
import enum, uuid
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from apps.extensions import db

class UserType(enum.Enum):   # 사용자 구분
    USER = 'user'
    EXPERT = 'expert'
    ADMIN = 'admin'
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, index=True)
    email = db.Column(db.String, unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    user_type = db.Column(db.Enum(UserType), nullable=False, default=UserType.USER)
    #is_admin=db.Column(db.Boolean,default=False)   # 코드 수정 최소화를 위해 잔류
    is_active = db.Column(db.Boolean, default=True)
    
    usage_count = db.Column(db.Integer, default=0)
    daily_limit = db.Column(db.Integer, default=1000)
    monthly_limit = db.Column(db.Integer, default=5000)
    
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    # 연관된 로그 (User가 삭제될 때 관련 로그는 유지)
    logs = db.relationship('Log', foreign_keys='Log.user_id', backref='actor', lazy='dynamic')
    #subscriptions = db.relationship('Subscription', backref='user', lazy=True, cascade='all, delete-orphan')
    #api_keys = db.relationship('APIKey', backref='user', lazy=True, cascade='all, delete-orphan')
    #usage_logs = db.relationship('UsageLog', backref='user', lazy=True, cascade='all, delete-orphan')
    #prediction_results = db.relationship('PredictionResult', backref='user', lazy=True, cascade="all, delete-orphan")
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
    # 이메일 중복 체크
    def is_duplicate_email(self):
        return User.query.filter_by(email=self.email).first() is not None
    def __repr__(self):
        return f'<User {self.username}>'
class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    # 로그를 발생시킨 사용자 (관리자 등)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), index=True, comment="행위를 수행한 사용자 ID")
    # 로그의 대상이 된 사용자
    target_user_id = db.Column(db.Integer, index=True, comment="행위의 대상이 된 사용자 ID")
    
    endpoint = db.Column(db.String(120), nullable=False)
    log_title = db.Column(db.String(50), nullable=False) # '삭제', '로그인', 'user_type change' 등
    log_summary = db.Column(db.Text)  # 변경 내용 요약
    timestamp = db.Column(db.DateTime, default=datetime.now, index=True)
    remote_addr = db.Column(db.String(45))
    response_status_code = db.Column(db.Integer)

    def __repr__(self) -> str:
        return f"<Log(user_id={self.user_id}, target_user_id={self.target_user_id}, log_title='{self.log_title}')>"
