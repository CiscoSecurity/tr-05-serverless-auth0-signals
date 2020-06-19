from functools import partial
from datetime import datetime

from flask import Blueprint, g, current_app

from api.schemas import ObservableSchema
from api.client import Auth0SignalsClient
from api.utils import get_json, get_jwt, jsonify_data, jsonify_result

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))


def extract_verdict(output, observable):

    valid_time = {
        'start_time': datetime.utcnow().isoformat() + 'Z'
    }

    score = int(output['fullip']['score'])
    doc = {
        'observable': observable,
        'disposition':
            current_app.config['SCORE_MAPPING'][score]['disposition'],
        'disposition_name':
            current_app.config['SCORE_MAPPING'][score]['disposition_name'],
        'valid_time': valid_time,
        'type': 'verdict'
    }

    return doc


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    client = Auth0SignalsClient(get_jwt())
    observables = get_observables()
    g.verdicts = []

    for observable in observables:
        if observable['type'] in current_app.config['SUPPORTED_TYPES']:
            response_data = client.get_auth0_signals_response(observable)
            if response_data:
                g.verdicts.append(extract_verdict(response_data, observable))

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    # Not implemented.
    return jsonify_data({})


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
