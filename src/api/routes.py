"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from werkzeug.security import generate_password_hash, check_password_hash
from base64 import b64encode
import os
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity


api = Blueprint('api', __name__)

def set_password(password, salt):
    return generate_password_hash(f"{password}{salt}")


def check_password(hash_password, password, salt):
    return check_password_hash(hash_password, f"{password}{salt}")


@api.route("/user", methods=["POST"])
def register_user():
    body = request.json
    email = body.get("email")
    password = body.get("password")

    if email is None or password is None:
        return jsonify({"message":"You need email and password"}), 400
    
    # me devuelve la primera coincidencia del dato que este filtrando
    # user = User.query.filter_by(email=email).first()
    
    # devuelve el dato solo y siempre sea unico registrado en la db
    user = User.query.filter_by(email=email).one_or_none()

    if user is not None:
        return jsonify({"message":"the user exists"}), 400
    
    else:
        salt = b64encode(os.urandom(32)).decode("utf-8")
        password = set_password(password, salt)
        user = User(email=email, password=password, salt=salt)
        db.session.add(user)

        try:
            db.session.commit()
            return jsonify({"message":"User created success"}), 201
        except Exception as error:
            db.session.rollback()
            return jsonify({"message":f"error: {error.args}"})



@api.route("/login", methods=["POST"])
def handle_login():
    body = request.json
    email = body.get("email")
    password = body.get("password")

    if email is None or password is None:
        return jsonify({"message":"You need email and password"}), 400
    else:
        user = User.query.filter_by(email=email).one_or_none()
        if user is None:
            return jsonify({"message":"Bad credentials"}), 400
        else:
            if check_password(user.password, password, user.salt):
                # le pasasmos un diccionario con lo necesario
                #OJO no se puede pasar informacion sencible por seguridad
                token = create_access_token(identity={
                    "user_id":user.id,
                    "rol":"general"
                })
                return jsonify({"token":token}), 200
            else:
                return jsonify({"message":"Bad credentials"}), 400
            

@api.route("/user", methods=["GET"])
@jwt_required()
def get_all_users():
    data_token = get_jwt_identity()
    if data_token.get("rol") == "admin":
        users = User.query.all()
        return jsonify(list(map(lambda item: item.serialize(), users)))
    else:
        return jsonify({"message":"no access"}), 401


@api.route("/user/<int:theid>", methods=["GET"])
def get_one_user(theid=None):
    user = User.query.get(theid)
    if user is None:
        return jsonify({"message":"user not found"}), 404
    return jsonify(user.serialize())
