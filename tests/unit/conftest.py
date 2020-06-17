import json
from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from authlib.jose import jwt
from pytest import fixture

from api.errors import UNAUTHORIZED, INVALID_ARGUMENT, PERMISSION_DENIED
from app import app


@fixture(scope='session')
def secret_key():
    # Generate some string based on the current datetime.
    return datetime.utcnow().isoformat()


@fixture(scope='session')
def client(secret_key):
    app.secret_key = secret_key

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    header = {'alg': 'HS256'}

    payload = {'username': 'gdavoian', 'superuser': False}

    secret_key = client.application.secret_key

    return jwt.encode(header, payload, secret_key).decode('ascii')


@fixture(scope='session')
def invalid_jwt(valid_jwt):
    header, payload, signature = valid_jwt.split('.')

    def jwt_decode(s: str) -> dict:
        from authlib.common.encoding import urlsafe_b64decode, json_loads
        return json_loads(urlsafe_b64decode(s.encode('ascii')))

    def jwt_encode(d: dict) -> str:
        from authlib.common.encoding import json_dumps, urlsafe_b64encode
        return urlsafe_b64encode(json_dumps(d).encode('ascii')).decode('ascii')

    payload = jwt_decode(payload)

    # Corrupt the valid JWT by tampering with its payload.
    payload['superuser'] = True

    payload = jwt_encode(payload)

    return '.'.join([header, payload, signature])


def auth0_signals_api_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or {}

    return mock_response


def auth0_signals_api_error_mock(status_code, text=None, reason=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.reason = reason

    return mock_response


def expected_payload(r, body):
    if r.endswith('/observe/observables'):
        return {'data': {}}

    return body


@fixture(scope='function')
def auth0_signals_health_check():
    return auth0_signals_api_response_mock(
        HTTPStatus.OK, payload={
            "fullip": {
                "geo": {
                    "country": "UA",
                    "country_names": {
                        "de": "Ukraine",
                        "en": "Ukraine",
                        "es": "Ucrania",
                        "fr": "Ukraine",
                        "ja": "ウクライナ共和国",
                        "pt-BR": "Ucrânia",
                        "ru": "Украина",
                        "zh-CN": "乌克兰"
                    },
                    "country_geoname_id": 690791,
                    "continent": "EU",
                    "continent_names": {
                        "de": "Europa",
                        "en": "Europe",
                        "es": "Europa",
                        "fr": "Europe",
                        "ja": "ヨーロッパ",
                        "pt-BR": "Europa",
                        "ru": "Европа",
                        "zh-CN": "欧洲"
                    },
                    "continent_geoname_id": 6255148,
                    "latitude": 0,
                    "longitude": 0,
                    "time_zone": "Europe/Kiev",
                    "region": "Dnipropetrovsk",
                    "region_names": {
                        "de": "Dnipropetrowsk",
                        "en": "Dnipropetrovsk",
                        "fr": "Oblast de Dnipropetrovsk",
                        "ru": "Днепропетровская область"
                    },
                    "region_geoname_id": 709929,
                    "city": "Dnipro",
                    "city_names": {
                        "de": "Dnipro",
                        "en": "Dnipro",
                        "es": "Dnipró",
                        "fr": "Dnipro",
                        "ja": "ドニプロペトロウシク",
                        "pt-BR": "Dnipro",
                        "ru": "Днепр",
                        "zh-CN": "第聂伯罗彼得罗夫斯克"
                    }
                }
            }
        }
    )


@fixture(scope='session')
def auth0_signals_response_unauthorized_creds(secret_key):
    return auth0_signals_api_error_mock(
        HTTPStatus.UNAUTHORIZED,
        'Unauthorized. API Key not found.',
        'Unauthorized'
    )


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return expected_payload(route, {
        'errors': [
            {'code': PERMISSION_DENIED,
             'message': 'Invalid Authorization Bearer JWT.',
             'type': 'fatal'}
        ],
        'data': {}
    })


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return expected_payload(
        route,
        {'errors': [
            {'code': INVALID_ARGUMENT,
             'message':
                 "Invalid JSON payload received. {0: {'value': "
                 "['Missing data for required field.']}}",
             'type': 'fatal'}],
            'data': {}}
    )


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):
    return expected_payload(
        route,
        {
            'errors': [
                {'code': UNAUTHORIZED,
                 'message': ("Unexpected response from Auth0 Signals: "
                             "Unauthorized. API Key not found."),
                 'type': 'fatal'}
            ],
            'data': {}
        }
    )
