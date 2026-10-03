"""
Checks for what CybICS installations send about themselves: identity at
enrolment and the status in every heartbeat. Shared by the CTF and the fleet
part. Device input is display data: it is clamped and scrubbed here so it can
never cause a 500, and nothing decides anything based on it.
"""
import json
import re

STATUS_MAX_BYTES = 16384
STATUS_MAX_DEPTH = 8
DEVICE_KINDS = ("virtual", "physical")
DEVICE_UID_RE = re.compile(r"[0-9a-f]{6,32}")


def encodable(value):
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def scrub(value):
    """Lone surrogates in an informational string become "?" instead of a 500."""
    return value if encodable(value) else value.encode("utf-8", "replace").decode("utf-8")


def opt_str(value, limit):
    return scrub(str(value))[:limit] if value not in (None, "") else None


def depth(value, limit=STATUS_MAX_DEPTH + 1):
    """Nesting depth of JSON data, iteratively and capped (no recursion to exploit)."""
    deepest, stack = 0, [(value, 1)]
    while stack:
        item, level = stack.pop()
        deepest = max(deepest, level)
        if deepest >= limit:
            return deepest
        if isinstance(item, dict):
            stack.extend((v, level + 1) for v in item.values())
        elif isinstance(item, list):
            stack.extend((v, level + 1) for v in item)
    return deepest


def clean_status(status):
    """
    (status dict, JSON to store or None) for a heartbeat's status. A missing
    status stores nothing, so the previous one stays; one that is too deep or
    too large is replaced by an error note, never stored.
    """
    info = status if isinstance(status, dict) else {}
    if not info:
        return info, None
    if depth(info) > STATUS_MAX_DEPTH:
        # Deep nesting is no status, it is an attack on whoever renders it
        # (Python's pretty-printer recurses). Never store it.
        info = {"error": "status too deeply nested, discarded"}
    status_json = json.dumps(info, separators=(",", ":"))
    if len(status_json) > STATUS_MAX_BYTES:
        info = {"error": "status too large, discarded"}
        status_json = json.dumps(info)
    return info, status_json


def parse_status(status_json):
    """A stored status as a dict; anything unreadable becomes {}."""
    try:
        status = json.loads(status_json or "{}")
    except (ValueError, RecursionError):
        return {}
    return status if isinstance(status, dict) else {}


def pretty_status(status):
    # Stored statuses are depth-checked, but rows from before that check may
    # not be; a broken status must never take the page down.
    try:
        return json.dumps(status, indent=2, sort_keys=True)[:4000]
    except (RecursionError, TypeError, ValueError):
        return "(status cannot be displayed)"


def device_info(info, error, field="instance"):
    """
    Validate the identity an installation sends: kind, STM32 UID, hostname,
    version, mode. `error(message)` builds the exception to raise.
    """
    if not isinstance(info, dict):
        raise error(f"{field} must be an object.")
    kind = info.get("kind")
    if kind not in DEVICE_KINDS:
        raise error(f"{field}.kind must be 'virtual' or 'physical'.")
    # Only a physical board has a UID; a virtual instance sending one is ignored.
    device_uid = (info.get("device_uid") or None) if kind == "physical" else None
    if device_uid is not None:
        device_uid = str(device_uid).lower()
        if not DEVICE_UID_RE.fullmatch(device_uid):
            raise error(f"{field}.device_uid must be hex (the STM32 UID).")
    if kind == "physical" and not device_uid:
        raise error(f"A physical {field} must send its device_uid.")
    return {"kind": kind, "device_uid": device_uid, "hostname": opt_str(info.get("hostname"), 64),
            "cybics_version": opt_str(info.get("cybics_version"), 32), "mode": opt_str(info.get("mode"), 32)}
