# app/models.py
from datetime import datetime
from app.extensions import db

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<User {self.name}>'
    
class API(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'price': self.price
        }
    
class PaymobOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, unique=True, nullable=False)  # Paymob order ID
    api_id = db.Column(db.Integer, db.ForeignKey('api.id')) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def __repr__(self):
        return f'<=Admin {self.name}>'

class PurchasedAPI(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    api_id = db.Column(db.Integer, db.ForeignKey('api.id'))
    transaction_id = db.Column(db.String(120), nullable=False)
    api_key = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)