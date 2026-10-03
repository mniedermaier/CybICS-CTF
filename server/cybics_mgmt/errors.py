"""Errors a caller can fix, shared by the CTF and the fleet parts."""


class MgmtError(Exception):
    """A request the caller can fix; carries an API error code and HTTP status."""

    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status
