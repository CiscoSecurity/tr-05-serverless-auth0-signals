import os

from version import VERSION


class Config:
    VERSION = VERSION

    SECRET_KEY = os.environ.get('SECRET_KEY', '')

    API_URL = 'https://signals.api.auth0.com/v2.0/'

    USER_AGENT = ('Cisco Threat Response Integrations '
                  '<tr-integrations-support@cisco.com>')
