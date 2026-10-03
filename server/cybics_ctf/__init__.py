"""
The server's package name before the rename to CybICS-mgmt. Kept so that
`flask --app cybics_ctf ...` in existing cron jobs and runbooks still works;
use `flask --app cybics_mgmt ...` for anything new.
"""
from cybics_mgmt import create_app  # noqa: F401
