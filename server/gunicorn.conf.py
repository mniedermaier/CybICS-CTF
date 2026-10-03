import os

# One worker: the rate limiter lives in process memory and SQLite serialises
# writes anyway. Threads cover concurrency; a CTF of a few hundred instances
# sends a handful of requests per second.
bind = "0.0.0.0:8000"
workers = 1
# Requests reach gunicorn fully buffered by the nginx proxy, so threads are
# only busy for the actual work.
threads = 16
timeout = 30
accesslog = "-"

# Which peers may set X-Forwarded-Proto and friends. Only the reverse proxy,
# never "*": otherwise any client could claim HTTPS. Set this to the proxy's
# address together with MGMT_TRUST_PROXY=1.
forwarded_allow_ips = os.environ.get("MGMT_FORWARDED_ALLOW_IPS", "").strip() or "127.0.0.1"

# The runtime control socket is not used, and its default location (the home
# directory) is read-only in the hardened container.
control_socket_disable = True
