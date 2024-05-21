from flask import current_app as app
from flask import Blueprint
from flask import request
from flask import jsonify
from ..models.extensions import db
from ..models.models import User
import uuid
import json
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

bcrypt = Bcrypt()

user_blueprint = Blueprint('user_blueprint', __name__)

@user_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    form = request.get_json()
    username = form.get("username")
    email = form.get("email")
    password = form.get("password")
    new_uuid = str(uuid.uuid4())
    hashed_password = bcrypt.generate_password_hash(password)

    new_user = User(
        user_id=new_uuid,
        username=username,
        email=email,
        password_hash=hashed_password
    )

    db.session.add(new_user)

    try:
        db.session.commit()
        return jsonify({"message":"User registered successfully"}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"message":str(e)}), 400

@user_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    form = request.get_json()
    identifier = form.get("username") or form.get("email")
    password = form.get("password")

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        access_token = create_access_token(identity=identifier)
        return jsonify({"message": "Login successful", "user_id": user.user_id, "access_token":access_token}), 200, {'ContentType':'application/json'}
    else:
        return jsonify({"message": "Unsuccessful Login"}), 401, {'ContentType':'application/json'}

@user_blueprint.route('/delete', methods=['GET','DELETE', 'POST'])
@jwt_required()
def deleteUser():
    form = request.get_json()
    identifier = form.get("username") or form.get("email")
    password = form.get("password")

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        db.session.delete(user)
        try:
            db.session.commit()
            return jsonify({"message":"User deleted successfully"}), 200
        except Exception as e:
            db.session.rollback()
            return jsonify({"message":str(e)}), 400
    else:
        return jsonify({"message":"User deletion unsuccessful, check that username, email, and password are correct"})

@user_blueprint.route('/update-username', methods=['GET', 'PATCH', 'POST'])
@jwt_required()
def updateUserUsername():
    form = request.get_json()
    username = form.get("username")
    new_username = form.get("new_username")
    password = form.get("password")

    user = User.query.filter((User.username == username)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        user.username = new_username
        try:
            db.session.commit()
            return jsonify({"message": "Username changed successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"message":str(e)}), 400
    else:
        return jsonify({"message":"Make sure to enter username and password correctly"})

@user_blueprint.route('/update-email', methods=['GET', 'PATCH', 'POST'])
@jwt_required()
def updateUserEmail():
    form = request.get_json()
    email = form.get("email")
    new_email = form.get("new_email")
    password = form.get("password")

    user = User.query.filter((User.email == email)).first()

    if user and bcrypt.check_password_hash(user.password_hash, password):
        user.email = new_email
        try:
            db.session.commit()
            return jsonify({"message": "Email changed successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"message":str(e)}), 400
    else:
        return jsonify({"message":"Make sure to enter email and password correctly"})


@user_blueprint.route('/update-password', methods=['GET', 'PATCH', 'POST'])
@jwt_required()
def updateUserPassword():
    form = request.get_json()
    identifier = form.get("username") or form.get("email")
    old_password = form.get("old_password")
    new_password = form.get("new_password")

    user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()

    if user and bcrypt.check_password_hash(user.password_hash, old_password):
        hashed_password = bcrypt.generate_password_hash(new_password)
        user.password_hash = hashed_password
        try:
            db.session.commit()
            return jsonify({"message": "Password changed successfully"})
        except Exception as e:
            db.session.rollback()
            return jsonify({"message":str(e)}), 400
    else:
        return jsonify({"message":"Make sure to enter username or email and old password correctly"})