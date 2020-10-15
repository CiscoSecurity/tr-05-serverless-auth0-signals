import requests
from http import HTTPStatus

from flask import current_app

from api.errors import CriticalError, AuthorizationError
from api.utils import join_url, ssl_error_handler


POTENTIALLY_NOT_CRITICAL_ERRORS = (
    HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND
)
INVALID_TOKEN_MESSAGE = 'Token must be a valid RFC4122 UUID'


class Auth0SignalsClient:
    def __init__(self, token):
        self.api_url = current_app.config['API_URL']
        self.headers = {
            'Accept': 'application/json',
            'X-Auth-Token': token,
            'User-Agent': current_app.config['USER_AGENT']
        }
        self.limit = current_app.config['CTR_ENTITIES_LIMIT']

    @ssl_error_handler
    def _get(self, url):
        response = requests.get(url, headers=self.headers)

        if response.ok:
            return response.json()

        if response.status_code in POTENTIALLY_NOT_CRITICAL_ERRORS:
            if INVALID_TOKEN_MESSAGE in response.text:
                raise AuthorizationError(INVALID_TOKEN_MESSAGE)
            return []
        elif response.status_code == HTTPStatus.UNAUTHORIZED:
            raise AuthorizationError(response.text)

        raise CriticalError(response)

    def get_auth0_response(self, observable):
        url = join_url(self.api_url, 'v2.0', 'ip', observable['value'])
        return self._get(url)

    def check_health(self):
        url = join_url(self.api_url, 'v2.0', 'ip')
        return self._get(url)

    @ssl_error_handler
    def get_details_of_the_list(self, blocklist_type, blocklist_id):
        url = join_url(
            self.api_url, 'metadata', blocklist_type, 'lists', blocklist_id
        )
        response = requests.get(url, headers=self.headers)
        return response.json()

    def get_full_details(self, response_data):
        result = []
        blocklists = {
            'badip': response_data['fullip']['badip']['blacklists'],
            'baddomain':
                [
                    *response_data['fullip']['baddomain']['domain'].get(
                        'blacklist', []
                    ),
                    *response_data['fullip']['baddomain']['domain'].get(
                        'blacklist_mx', []
                    ),
                    *response_data['fullip']['baddomain']['domain'].get(
                        'blacklist_ns', []
                    )
                ]
        }

        for blocklist_type, blocklist_ids in blocklists.items():
            for list_id in blocklist_ids:
                result.append(
                    self.get_details_of_the_list(blocklist_type, list_id)
                )
                if len(result) == self.limit:
                    return result

        return result
