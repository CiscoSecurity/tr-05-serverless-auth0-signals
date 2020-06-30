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
        if observable['type'] == 'ip':
            response_data = client.get(observable)
            if response_data:
                g.verdicts.append(extract_verdict(response_data, observable))

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    # Not implemented.
    return jsonify_data({})


def get_search_pivot(value):
    return {
        'id': f'ref-auth0-signals-search-ip-{value}',
        'title':
            'Search for this IP',
        'description':
            'Lookup this IP on Auth0 Signals',
        'url': current_app.config['UI_URL'].format(
            value=value
        ),
        'categories': ['Search', 'Auth0 Signals'],
    }


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    observables = get_observables()
    data = []

    for observable in observables:
        value = observable['value']
        type_ = observable['type'].lower()
        if type_ == 'ip':
            data.append(get_search_pivot(value))
    return jsonify_data(data)
