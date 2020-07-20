from functools import partial
from datetime import datetime, timedelta
from uuid import uuid4

from flask import Blueprint, g, current_app

from api.schemas import ObservableSchema
from api.client import Auth0SignalsClient
from api.utils import get_json, get_jwt, jsonify_data, jsonify_result

enrich_api = Blueprint('enrich', __name__)


get_observables = partial(get_json, schema=ObservableSchema(many=True))
JUDJEMENT_RELEVANCE_PERIOD = timedelta(days=7)


def time_to_ctr_format(time):
    return time.isoformat() + 'Z'


def extract_verdict(output, observable):
    score = int(output['fullip']['score'])
    doc = {
        'observable': observable,
        'disposition':
            current_app.config['SCORE_MAPPING'][score]['disposition'],
        'disposition_name':
            current_app.config['SCORE_MAPPING'][score]['disposition_name'],
        'valid_time': {},
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


def extract_judgements(output, observable):
    start_time = datetime.utcnow()
    end_time = start_time + JUDJEMENT_RELEVANCE_PERIOD
    docs = [
        {
            'observable': observable,
            'reason': current_app.config['REASON_MAPPING'][score_element],
            'source_uri': current_app.config['UI_URL'].format(
                value=observable['value']
            ),
            'id': f'transient:judgement-{uuid4()}',
            'valid_time': {
                'start_time': time_to_ctr_format(start_time),
                'end_time': time_to_ctr_format(end_time),
            },
            **current_app.config['CTIM_JUDGEMENT_DEFAULTS']
        }
        for score_element in current_app.config['REASON_MAPPING']
        if int(output['fullip'][score_element]['score']) < 0
    ]

    return docs


def get_severity(blocklist):
    severity_mapping = {'1': 'High', '5': 'Medium', '10': 'Info'}
    return severity_mapping[blocklist['sensitivity']]


def get_tlp(blocklist):
    if blocklist['visibility'] == 'Public':
        return 'white'
    return 'amber'


def extract_sightings(details):
    start_time = time_to_ctr_format(datetime.utcnow())
    docs = [
        {
            'source': blocklist['source'],
            'source_uri': blocklist['site'],
            'observed_time': {
                'start_time': start_time,
                'end_time': start_time,
            },
            'id': f'transient:sighting-{uuid4()}',
            'tlp': get_tlp(blocklist),
            'severity': get_severity(blocklist),
            **current_app.config['CTIM_SIGHTING_DEFAULTS']
        }
        for blocklist in details
    ]
    return docs


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    client = Auth0SignalsClient(get_jwt())
    observables = get_observables()
    g.verdicts = []
    g.judgements = []
    g.sightings = []

    for observable in observables:
        if observable['type'] == 'ip':
            response_data = client.get(observable)
            if response_data:
                g.verdicts.append(extract_verdict(response_data, observable))
                g.judgements.extend(
                    extract_judgements(response_data, observable)
                )
                details = client.get_full_details(response_data)
                g.sightings.extend(extract_sightings(details))

    return jsonify_result()


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
