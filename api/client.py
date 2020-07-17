import requests
from http import HTTPStatus

from flask import current_app

from api.errors import CriticalError
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

        raise CriticalError(response)

    def check_health(self):
        url = join_url(self.api_url, 'ip')

        response = requests.get(url, headers=self.headers)

        if not response.ok:
            raise CriticalError(response)

    def get_the_full_details_of_the_list(self, response_data):
        result = []  # ToDo Add Limit, Refactor
        blocklists_badip = response_data['fullip']['badip']['blacklists']
        blocklists_baddomain = []
        for i in [response_data['fullip']['baddomain']['domain'].get('blacklist'),
                  response_data['fullip']['baddomain']['domain'].get('blacklist_mx'),
                  response_data['fullip']['baddomain']['domain'].get('blacklist_ns')]:
            if i:
                blocklists_baddomain.extend(i)
        for list_id in blocklists_badip:
            response = requests.get(current_app.config['METADATA_URL'].format(blocklist_type='badip', blocklist_id=list_id),
                                    headers=self.headers)
            result.append(response.json())
        for list_id in blocklists_baddomain:
            response = requests.get(current_app.config['METADATA_URL'].format(blocklist_type='baddomain', blocklist_id=list_id),
                                    headers=self.headers)
            result.append(response.json())

        return result
