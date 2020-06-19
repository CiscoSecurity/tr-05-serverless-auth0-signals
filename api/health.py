from flask import Blueprint


from api.utils import get_jwt, jsonify_data
from api.client import Auth0SignalsClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    client = Auth0SignalsClient(get_jwt())
    _ = client.check_auth0_signals_health()
    return jsonify_data({'status': 'ok'})
