from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock
from requests.exceptions import SSLError

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


@fixture(scope='function')
def auth0_signals_response_ok():
    return auth0_signals_api_response_mock(
        HTTPStatus.OK, payload={
            "fullip": {
                "geo": {
                    "address": "79.143.44.122",
                    "hostname": "79.143.44.122.vntp.net",
                    "country": "UA",
                    "country_names": {
                        "de": "Ukraine",
                        "en": "Ukraine"
                    },
                    "country_geoname_id": 690791,
                    "continent": "EU",
                    "continent_names": {
                        "de": "Europa",
                        "en": "Europe"
                    },
                    "region_geoname_id": 689559,
                    "city": "Vinnytsia",
                    "city_names": {
                        "de": "Winnyzja",
                        "en": "Vinnytsia"
                    }
                },
                "hostname": "79.143.44.122.vntp.net",
                "baddomain": {
                    "domain": {
                        "blacklist": [],
                        "blacklist_mx": [],
                        "blacklist_ns": [],
                        "mx": [],
                        "ns": [],
                        "score": 0
                    },
                    "ip": {
                        "address": "",
                        "blacklist": "",
                        "score": 0
                    },
                    "source_ip": {
                        "address": "188.163.44.200",
                        "blacklist": [],
                        "score": 0
                    },
                    "score": 0
                },
                "badip": {
                    "score": -1,
                    "blacklists": [
                        "FAIL2BAN-SSH"
                    ]
                },
                "history": {
                    "score": -1,
                    "activity": [
                        {
                            "ip": "79.143.44.122",
                            "timestamp": 1594894842846,
                            "command": "add",
                            "blacklists": "FAIL2BAN-SSH,STOPFORUMSPAM-365",
                            "blacklist_change": "FAIL2BAN-SSH"
                        },
                        {
                            "ip": "79.143.44.122",
                            "timestamp": 1594891098116,
                            "command": "rem",
                            "blacklists": "STOPFORUMSPAM-365",
                            "blacklist_change": "FAIL2BAN-SSH"
                        }
                    ],
                },
                "score": -2,
            }
        }
    )


@fixture(scope='function')
def auth0_signals_response_details():
    return auth0_signals_api_response_mock(
        HTTPStatus.OK, payload={
            "name": "FAIL2BAN-SSH Blocklist.de",
            "refresh": "60  minutes",
            "source": "Fail2Ban and Blocklist.de services",
            "type": "badip",
            "enabled": "True",
            "tags": "reputation,abuse,bruteforce",
            "group": "abuse",
            "count": "16407",
            "sensitivity": "1",
            "last_update": "1594984501",
            "site": "http://www.blocklist.de",
            "visibility": "Public",
            "description": "www.blocklist.de is a free and voluntary "
                           "service provided by a Fraud/Abuse-specialist, "
                           "whose servers are often attacked on SSH-, "
                           "Mail-Login-, FTP-, Webserver- and other services."
        }
    )


def auth0_signals_api_response_mock(status_code, payload=None):
    mock_response = MagicMock()

    mock_response.status = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    payload = payload or {}

    mock_response.json = lambda: payload

    return mock_response


def auth0_signals_api_error_mock(status_code, text=None, reason=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.text = text
    mock_response.reason = reason

    return mock_response


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


@fixture(scope='session')
def auth0_signals_bad_request(secret_key):
    return auth0_signals_api_error_mock(
        HTTPStatus.BAD_REQUEST,
        'Bad IP format:*@^',
        'Bad Request'
    )


@fixture(scope='module')
def invalid_jwt_expected_payload(route):
    return {
        'errors': [
            {'code': PERMISSION_DENIED,
             'message': 'Invalid Authorization Bearer JWT.',
             'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def invalid_json_expected_payload(route):
    return {
        'errors': [
            {'code': INVALID_ARGUMENT,
             'message':
                 "Invalid JSON payload received. {0: {'value': "
                 "['Missing data for required field.']}}",
             'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def unauthorized_creds_expected_payload(route):
    return {
        'errors': [
            {'code': UNAUTHORIZED,
             'message': ('Unexpected response from Auth0 Signals: '
                         'Unauthorized. API Key not found.'),
             'type': 'fatal'}
        ],
        'data': {}
    }


@fixture(scope='module')
def success_deliberate_body():
    return {
        "data": {
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "ip",
                            "value": "1.1.1.1"
                        },
                        "type": "verdict",
                    }
                ]
            }
        }
    }


@fixture(scope='session')
def auth0_ssl_exception_mock(secret_key):
    mock_exception = MagicMock()
    mock_exception.reason.args.__getitem__().verify_message \
        = 'self signed certificate'
    return SSLError(mock_exception)


@fixture(scope='module')
def ssl_error_expected_payload(route, client):
    if route in ('/observe/observables', '/health'):
        return {
            'data': {},
            'errors': [
                {
                    'code': 'unknown',
                    'message': 'Unable to verify SSL certificate: '
                               'Self signed certificate',
                    'type': 'fatal'
                }
            ]
        }

    if route.endswith('/deliberate/observables'):
        return {'data': {}}

    return {'data': []}


@fixture(scope='module')
def success_refer_body():
    return {
        "data":
            [
                {
                    "categories": [
                        "Search",
                        "Auth0 Signals"
                    ],
                    "description": "Lookup this IP on Auth0 Signals",
                    "id": "ref-auth0-signals-search-ip-1.1.1.1",
                    "title": "Search for this IP",
                    "url": "https://auth0.com/signals/ip/1.1.1.1-report"
                }
            ]
    }


@fixture(scope='module')
def success_observe_body():
    return {
        "data": {
            "judgements": {
                "count": 2,
                "docs": [
                    {
                        "confidence": "High",
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "ip",
                            "value": "1.1.1.1"
                        },
                        "priority": 90,
                        "reason": "IP found on blocklist",
                        "schema_version": "1.0.17",
                        "severity": "Medium",
                        "source": "Auth0 Signals Report",
                        "source_uri": "https://auth0.com/signals/ip/"
                                      "1.1.1.1-report",
                        "type": "judgement"
                    },
                    {
                        "confidence": "High",
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "ip",
                            "value": "1.1.1.1"
                        },
                        "priority": 90,
                        "reason": "IP found on blocklist in recent past",
                        "schema_version": "1.0.17",
                        "severity": "Medium",
                        "source": "Auth0 Signals Report",
                        "source_uri": "https://auth0.com/signals/ip/"
                                      "1.1.1.1-report",
                        "type": "judgement",
                    }
                ]
            },
            "sightings": {
                "count": 1,
                "docs": [
                    {
                        "confidence": "High",
                        "count": 1,
                        "description": "Found on blocklist",
                        "schema_version": "1.0.17",
                        "source": "Fail2Ban and Blocklist.de services",
                        "source_uri": "http://www.blocklist.de",
                        "type": "sighting",
                        "tlp": "white",
                        "severity": "High",
                        "observables": [
                            {
                                "type": "ip",
                                "value": "1.1.1.1"
                            }
                        ],
                    }
                ]
            },
            "indicators": {
                "count": 1,
                "docs": [
                    {
                        "description": "www.blocklist.de is a free and "
                                       "voluntary service provided by "
                                       "a Fraud/Abuse-specialist, whose "
                                       "servers are often attacked on SSH-, "
                                       "Mail-Login-, FTP-, Webserver- "
                                       "and other services.",
                        "producer": "Fail2Ban and Blocklist.de services",
                        "schema_version": "1.0.17",
                        "short_description": "Feed: FAIL2BAN-SSH Blocklist.de",
                        "tags": [
                            "reputation",
                            "abuse",
                            "bruteforce"
                        ],
                        "title": "FAIL2BAN-SSH Blocklist.de",
                        "type": "indicator",
                        "valid_time": {}
                    }
                ]
            },
            "verdicts": {
                "count": 1,
                "docs": [
                    {
                        "disposition": 3,
                        "disposition_name": "Suspicious",
                        "observable": {
                            "type": "ip",
                            "value": "1.1.1.1"
                        },
                        "type": "verdict",
                    }
                ]
            },
            "relationships": {
                "count": 1,
                "docs": [
                    {
                        "relationship_type": "member-of",
                        "schema_version": "1.0.17",
                        "type": "relationship"
                    }
                ]
            }
        }
    }


@fixture(scope='module')
def success_enrich_expected_payload(
        route, success_deliberate_body,
        success_refer_body, success_observe_body
):
    payload_to_route_match = {
        '/deliberate/observables': success_deliberate_body,
        '/refer/observables': success_refer_body,
        '/observe/observables': success_observe_body
    }
    return payload_to_route_match[route]
