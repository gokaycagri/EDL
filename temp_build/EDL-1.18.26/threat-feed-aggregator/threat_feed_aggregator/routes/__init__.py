from flask import Blueprint

# Initialize Blueprints
bp_dashboard = Blueprint('dashboard', __name__)
bp_api = Blueprint('api', __name__, url_prefix='/api')
bp_auth = Blueprint('auth', __name__)
bp_system = Blueprint('system', __name__, url_prefix='/system')

# Import views to register routes
from . import api, auth, dashboard, system
