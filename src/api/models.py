from flask_sqlalchemy import SQLAlchemy
from enum import Enum

db = SQLAlchemy()

class UserGender(Enum):
    male="male",
    female="female",
    other="other"


class UserRol(Enum):
    admin="admin",
    general="general"


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(180), unique=False, nullable=False)
    salt = db.Column(db.String(80), unique=False, nullable=False)
    rol = db.Column(db.Enum(UserRol), nullable=False, default="general")
    gender = db.Column(db.Enum(UserGender), nullable=False)
    

    def __repr__(self):
        return f'<User {self.email}>'

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "rol":self.rol.value,
            "gender":self.gender.value
            # do not serialize the password, its a security breach
        }
    
