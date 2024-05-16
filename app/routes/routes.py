from flask import current_app as app
from flask import Blueprint

temp_blueprint = Blueprint('temp_blueprint', __name__)



@temp_blueprint.route('/')
@temp_blueprint.route('/index')
def index():
    return "Hello, World!"