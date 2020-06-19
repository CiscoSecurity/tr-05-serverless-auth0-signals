from http import HTTPStatus

from pytest import fixture

from unittest.mock import patch

from .utils import headers


def routes():
    yield '/deliberate/observables'
    yield '/observe/observables'
    yield '/refer/observables'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_enrich_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@fixture(scope='module')
def invalid_json():
    return [{'type': 'domain'}]


def test_enrich_call_with_valid_jwt_but_invalid_json_failure(
        route, client, valid_jwt,
        invalid_json, invalid_json_expected_payload
):
    response = client.post(route,
                           headers=headers(valid_jwt),
                           json=invalid_json)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload


@fixture(scope='module')
def valid_json():
    return [{'type': 'ip', 'value': '1.1.1.1'}]


@patch('requests.get')
def test_enrich_call_success(
        get_mock, route, client, valid_jwt,
        valid_json, auth0_signals_response_ok,
        success_enrich_expected_payload
):
    get_mock.return_value = auth0_signals_response_ok
    response = client.post(route, headers=headers(valid_jwt), json=valid_json)
    assert response.status_code == HTTPStatus.OK
    response = response.get_json()
    assert response.get('errors') is None

    if response.get('data') and response['data'].get('verdicts'):
        assert response['data']['verdicts']['docs'][0].pop('valid_time')

    assert response == success_enrich_expected_payload


@fixture(scope='module')
def valid_json_multiple():
    return [{'type': 'ip', 'value': '1.1.1.1'},
            {'type': 'ip', 'value': '*@^'},
            {'type': 'ip', 'value': '1.1.1.3'}]


@patch('requests.get')
def test_enrich_call_success_with_extended_error_handling(
        get_mock, route, client, valid_jwt, valid_json_multiple,
        auth0_signals_response_ok, success_enrich_expected_payload,
        auth0_signals_response_unauthorized_creds,
        auth0_signals_bad_request, unauthorized_creds_expected_payload
):
    if route == '/deliberate/observables':
        get_mock.side_effect = [
            auth0_signals_response_ok,
            auth0_signals_bad_request,
            auth0_signals_response_unauthorized_creds
        ]
        response = client.post(
            route, headers=headers(valid_jwt), json=valid_json_multiple
        )
        assert response.status_code == HTTPStatus.OK

        response = response.get_json()

        assert response['data']['verdicts']['docs'][0].pop('valid_time')

        expected_result = {}
        expected_result.update(unauthorized_creds_expected_payload)
        expected_result.update(success_enrich_expected_payload)

        assert response == expected_result
