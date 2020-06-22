import requests
from http import HTTPStatus

from flask import current_app

from api.errors import UnexpectedResponseError
from api.utils import join_url


NOT_CRITICAL_ERRORS = (HTTPStatus.BAD_REQUEST, HTTPStatus.NOT_FOUND)


class Auth0SignalsClient:
    def __init__(self, token):
        self.api_url = current_app.config['API_URL']
        self.headers = {
            'Accept': 'application/json',
            'X-Auth-Token': token.get('key'),
            'User-Agent': current_app.config['USER_AGENT']
        }

    def get(self, observable):
        url = join_url(self.api_url, 'ip', observable['value'])

        response = requests.get(url, headers=self.headers)

        if response.ok:
            return response.json()

        if response.status_code in NOT_CRITICAL_ERRORS:
            return []

        raise UnexpectedResponseError(response)

    def check_health(self):
        url = join_url(self.api_url, 'ip')

        response = requests.get(url, headers=self.headers)

        if not response.ok:
            raise UnexpectedResponseError(response)
