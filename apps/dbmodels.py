# apps/dbmodels.py
import enum, uuid
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from apps.extensions import db

class UserType(enum.Enum):   # 사용자 구분
    ADMIN = 'admin'
    USER = 'user'
    EXPERT = 'expert'
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
