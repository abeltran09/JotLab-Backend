from flask import current_app as app
from flask import Blueprint
from flask import request
from ..models.extensions import db
from ..models.models import User
import uuid

temp_blueprint = Blueprint('temp_blueprint', __name__)



@temp_blueprint.route('/', methods=['POST'])
@temp_blueprint.route('/index', methods=['POST'])
def index():
    return "Hello, World!"
