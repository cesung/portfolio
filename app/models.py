import geocoder
from datetime import datetime
from flask_login import UserMixin
from app import db, login_manager, app
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    role = db.Column(db.String(20), unique=False, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    gender = db.Column(db.String(5), unique=False, nullable=False)
    # hash the image into string format
    profile_picture = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    # one-to-many relationship
    posts = db.relationship('Article', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None

        return User.query.get(user_id)

    def __repr__(self):
        return f"User('{self.username}', '{self.role}', '{self.gender}', '{self.email}', '{self.profile_picture}')"

class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20), nullable=False)
    location = db.Column(db.String(20), nullable=False, default=geocoder.ip("me").city)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    category = db.Column(db.String(20), nullable=False, default="Trivial")
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    def __repr__(self):
        return f"Article('{self.title}', '{self.date_posted}')"

class Quote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.String(500), nullable=False, default="")

    def __repr__(self):
        return f"Quote('{self.date}', '{self.content}')"
