import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://signals.api.auth0.com/v2.0/'

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
