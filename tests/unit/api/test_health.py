from http import HTTPStatus

from unittest.mock import patch

from pytest import fixture

from .utils import headers


def routes():
    yield '/health'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


def test_health_call_without_jwt_failure(
        route, client, invalid_jwt_expected_payload
):
    response = client.post(route)

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


def test_health_call_with_invalid_jwt_failure(
        route, client, invalid_jwt, invalid_jwt_expected_payload
):
    response = client.post(route, headers=headers(invalid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_jwt_expected_payload


@patch('requests.get')
def test_health_call_with_unauthorized_creds_failure(
        get_mock, route, client, valid_jwt,
        auth0_signals_response_unauthorized_creds,
        unauthorized_creds_expected_payload,
):

    get_mock.return_value = auth0_signals_response_unauthorized_creds
    response = client.post(
        route, headers=headers(valid_jwt)
    )

    assert response.status_code == HTTPStatus.OK
    assert response.json == unauthorized_creds_expected_payload


@patch('requests.get')
def test_health_call_success(
        get_mock, route, client, valid_jwt,
        auth0_signals_health_check
):
    get_mock.return_value = auth0_signals_health_check
    response = client.post(route, headers=headers(valid_jwt))

    assert response.status_code == HTTPStatus.OK
    assert response.json == {'data': {'status': 'ok'}}


@patch('requests.get')
def test_health_with_ssl_error(
        mock_request, route, client, valid_jwt,
        auth0_ssl_exception_mock,
        ssl_error_expected_payload
):
    mock_request.side_effect = auth0_ssl_exception_mock

    response = client.post(
        route, headers=headers(valid_jwt)
    )

    assert response.status_code == HTTPStatus.OK

    response = response.get_json()
    assert response == ssl_error_expected_payload
