import requests
from flask import Blueprint, current_app

from api.errors import UnexpectedResponseError
from api.utils import jsonify_data, get_jwt, join_url

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    token = get_jwt()

    url = join_url(current_app.config['API_URL'], 'ip')

    headers = {
        'Accept': 'application/json',
        'X-Auth-Token': token.get('key'),
        'User-Agent': current_app.config['USER_AGENT']

    }

    response = requests.get(url, headers=headers)

    if response.ok:
        return jsonify_data({'status': 'ok'})

    raise UnexpectedResponseError(response)
