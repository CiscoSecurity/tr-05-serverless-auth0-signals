import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://signals.api.auth0.com/'
    UI_URL = 'https://auth0.com/signals/ip/{value}-report'

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')

    SCORE_MAPPING = {
        0: {
            "disposition": 5,
            "disposition_name": "Unknown",
        },
        -1: {
            "disposition": 3,
            "disposition_name": "Suspicious",
        },
        -2: {
            "disposition": 3,
            "disposition_name": "Suspicious",
        },
        -3: {
            "disposition": 2,
            "disposition_name": "Malicious",
        }
    }

    REASON_MAPPING = {
        'baddomain': 'Associated hostname found on blocklist',
        'badip': 'IP found on blocklist',
        'history': 'IP found on blocklist in recent past'
    }

    CTIM_SCHEMA_VERSION = '1.0.17'

    CTIM_JUDGEMENT_DEFAULTS = {
        'type': 'judgement',
        'disposition': 3,
        'disposition_name': 'Suspicious',
        'schema_version': CTIM_SCHEMA_VERSION,
        'source': 'Auth0 Signals Report',
        'confidence': 'High',
        'severity': 'Medium',
        'priority': 90,
    }

    CTIM_SIGHTING_DEFAULTS = {
        'type': 'sighting',
        'count': 1,
        'confidence': 'High',
        'schema_version': CTIM_SCHEMA_VERSION,
        'description': 'Found on blocklist'
    }

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    try:
        CTR_ENTITIES_LIMIT = int(os.environ['CTR_ENTITIES_LIMIT'])
        assert CTR_ENTITIES_LIMIT > 0
    except (KeyError, ValueError, AssertionError):
        CTR_ENTITIES_LIMIT = CTR_DEFAULT_ENTITIES_LIMIT
