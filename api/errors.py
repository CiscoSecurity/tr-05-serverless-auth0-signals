INVALID_ARGUMENT = 'invalid argument'
PERMISSION_DENIED = 'permission denied'
UNKNOWN = 'unknown'
UNAUTHORIZED = 'unauthorized'


class TRFormattedError(Exception):
    def __init__(self, code, message, type_='fatal'):
        super().__init__()
        self.code = code.lower() or UNKNOWN
        self.message = message or 'Something went wrong.'
        self.type_ = type_

    @property
    def json(self):
        return {'type': self.type_,
                'code': self.code,
                'message': self.message}


class InvalidJWTError(TRFormattedError):
    def __init__(self):
        super().__init__(
            PERMISSION_DENIED,
            'Invalid Authorization Bearer JWT.'
        )


class InvalidArgumentError(TRFormattedError):
    def __init__(self, message):
        super().__init__(
            INVALID_ARGUMENT,
            f'Invalid JSON payload received. {message}'
        )


class UnsupportedObservableTypeError(InvalidArgumentError):
    def __init__(self, type_):
        super().__init__(
            f'Unsupported observable error: {type_}'
        )


class UnexpectedResponseError(TRFormattedError):
    def __init__(self, response):
        super().__init__(
            response.reason,
            f'Unexpected response from Auth0 Signals: {response.text}'
        )
