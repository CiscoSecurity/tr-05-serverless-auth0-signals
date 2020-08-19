from authlib.jose import jwt
from authlib.jose.errors import JoseError
from flask import request, current_app, jsonify, g
from requests.exceptions import SSLError

from api.errors import InvalidJWTError, InvalidArgumentError, Auth0SSLError


def get_jwt():
    try:
        scheme, token = request.headers['Authorization'].split()
        assert scheme.lower() == 'bearer'
        return jwt.decode(token, current_app.config['SECRET_KEY'])
    except (KeyError, ValueError, AssertionError, JoseError):
        raise InvalidJWTError


def get_json(schema):
    data = request.get_json(force=True, silent=True, cache=False)

    message = schema.validate(data)

    if message:
        raise InvalidArgumentError(message)

    return data


def format_docs(docs):
    return {'count': len(docs), 'docs': docs}


def jsonify_data(data):
    return jsonify({'data': data})


def jsonify_result():
    result = {'data': {}}

    if g.get('verdicts'):
        result['data']['verdicts'] = format_docs(g.verdicts)
    if g.get('judgements'):
        result['data']['judgements'] = format_docs(g.judgements)
    if g.get('sightings'):
        result['data']['sightings'] = format_docs(g.sightings)
    if g.get('indicators'):
        result['data']['indicators'] = format_docs(g.indicators)
    if g.get('relationships'):
        result['data']['relationships'] = format_docs(g.relationships)

    if g.get('errors'):
        result['errors'] = g.errors

    return jsonify(result)


def join_url(base, *parts):
    return '/'.join(
        [base.rstrip('/')] +
        [part.strip('/') for part in parts]
    )


def ssl_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SSLError as error:
            raise Auth0SSLError(error)
    return wrapper
