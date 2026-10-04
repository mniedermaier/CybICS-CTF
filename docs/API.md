# API v1

Base path: `/api/v1`. All request and response bodies are JSON, except the log upload of a job.

This is the contract with CybICS from the release that replaces v1.2.4 on, which ships the client
(`software/landing/modules/cybics_mgmt.py`). Changes under `/api/v1` may only add fields or
endpoints; anything else needs `/api/v2`, served alongside v1. Clients ignore fields they do not
know.

- **One identity.** A CybICS installation enrols once as a **device** (`POST /enroll`) and gets a
  bearer token. That token authenticates every other call, the CTF ones included. Joining a team in
  an event is a separate step (`POST /ctf/join`) for the enrolled device.
- **Authentication.** Endpoints marked 🔒 need `Authorization: Bearer <token>`.
- **Errors.** Every error has the same shape. Show `message` to the user unchanged:

```json
{"error": {"code": "wrong_team_password", "message": "Wrong password for this team."}}
```

| HTTP | Meaning for the client |
|---|---|
| 400 | Bad input; see `code`: `invalid_json`, `invalid_input` (a field of the wrong JSON type), `invalid_device`, `invalid_team_name`, `invalid_team_password`, `weak_team_password`. |
| 401 `unauthorized` | Token unknown, or the device was retired (by the organiser, or because the user disconnected it). Stop syncing and ask the user to connect again. Repeated *unknown* tokens from one address are rate limited; a valid token is never limited by that, so garbage from a shared NAT address cannot stall honest devices behind it. |
| 403 | `code_disabled`, `wrong_team_password`, `registration_closed`, `team_banned`. `team_banned` is not permanent: the organiser can reinstate the team, so keep retrying with backoff. |
| 404 | `invalid_code`, `invalid_join_code`, `not_found`. |
| 409 | `not_in_event` (the device is in no event), `event_finished`, `team_name_taken`, `too_many_instances` (25 live devices per team). |
| 413 | Body too large: 16 KB for `/enroll` and `/ctf/join`, 64 KB for the rest of the API, 256 KB for a log bundle. |
| 429 `rate_limited` | Back off. Also `too_many_instances` when more than 100 devices joined a team within an hour. |
| 503 `busy` | No password-hashing slot within 2 s, or the team changed during the request. Retry after a few seconds. |
| 4xx without this JSON shape | Not from this server (a reverse proxy's error page while the backend restarts). Treat it like a 5xx: keep queued data and retry. |
| 5xx / no answer | Transient. Keep queued data and retry later. |

---

## `GET /info`

Unauthenticated. The landing page's **Test connection** button calls this.

```json
{"service": "cybics-mgmt", "name": "CybICS-mgmt", "version": "0.1.0", "api_version": 1,
 "server_time": 1790844304.29}
```

`service` is always `"cybics-mgmt"`; the client compares it to tell this server from any other.
`name` is the display name the organiser configured (`MGMT_SERVER_NAME`).

## `POST /enroll`

Enrols the installation as a device. `code` is an enrolment code from the organiser's *Fleet →
Groups & codes* page, or the join code of an event that is not finished, so participants can connect
with the one code they were given. A device that enrols with an enrolment code joins that code's
group. Enrolling never joins an event; that is `POST /ctf/join`.

The proxy holds `/enroll` and `/ctf/join` together to 8 requests per second per address, and queues
bursts instead of refusing them.

```json
{
  "code": "7KQ2MWXA",
  "label": "Board 7",                 // optional, at most 40 characters; the organiser can change it
  "device": {
    "kind": "physical",               // "virtual" | "physical"
    "device_uid": "0042001a3133",     // STM32 UID, 6 to 32 hex digits; required for physical
    "hostname": "cybics",
    "cybics_version": "1.2.3",
    "mode": "full"                    // cybics.sh --mode, if known
  }
}
```

`201`:

```json
{
  "device_id": "0b6f…",
  "token": "…",                       // returned only once; the server keeps a hash
  "device": {"id": "0b6f…", "label": "Board 7", "group": "Room 2"},
  "signing_key": {"n": "c3a1…", "e": 65537, "fingerprint": "9f2c…"},
  "heartbeat_interval": 30
}
```

- `signing_key` is the RSA key the server signs jobs with: modulus `n` in hex (at least 3072 bits)
  and exponent `e`. The client pins it and runs only jobs that verify against it. `fingerprint` is
  the SHA-256 of `"<e>:<n in hex>"` (lower-case hex); the organiser's device page and the landing
  page both show it.
- Unknown code (or the join code of a finished event): `404 invalid_code`. Disabled code:
  `403 code_disabled`. Malformed `device`: `400 invalid_device`. `device_uid` is ignored for
  virtual devices.
- Every enrolment creates a new device. The board UID is never used to authenticate or to merge
  devices: it is broadcast in the SSID.
- Flood guards per address, both shown on the organiser's *Events* page with a button to clear them:
  60 unknown codes per minute, and 100 new devices per 10 minutes. Only devices actually created
  count.

## 🔒 `POST /heartbeat`

Every `heartbeat_interval` seconds, at most 30 per device and minute. One heartbeat carries
everything: the device's status, what it allows, the results of finished jobs, and the last
announcement it has shown.

```json
{
  "status": {
    "cybics_version": "1.2.3",
    "mode": "full",
    "hostname": "cybics",
    "services": {"openplc": true, "fuxa": true, "opcua": true, "s7com": false},
    "local_solved": ["scanning", "opcua"]
  },
  "management": {
    "allowed": ["identify", "restart"],   // actions the user allowed on the device
    "key_fingerprint": "9f2c…",          // of the key it pinned
    "client": "1"
  },
  "job_results": [{"id": "5e1d…", "seq": 3, "state": "done", "detail": "restarted openplc"}],
  "announcements_after": 4                // id of the last announcement already shown
}
```

- Everything in `status` is optional. It is stored as the device's last status, up to 16 KB and a
  nesting depth of 8; anything larger or deeper is replaced by an error note. A heartbeat without
  `status` keeps the previous one. `cybics_version`, `mode` and `hostname` update the device's
  columns.
- `management` replaces what the server knows about the device's management; without it, nothing
  is allowed. Unknown actions are dropped.
- `job_results` finishes jobs: `state` is `done`, `failed` or `refused`, `detail` at most 500
  characters. Any other state counts as `failed`. Results for jobs of other devices are ignored.

`200`:

```json
{
  "device": {"id": "0b6f…", "label": "Board 7", "group": "Room 2"},
  "jobs": [{"id": "5e1d…", "device": "0b6f…", "seq": 3, "action": "restart",
            "params": {"service": "openplc"}, "signature": "8d07…"}],
  "signing_key_fingerprint": "9f2c…",
  "heartbeat_interval": 30,              // the client clamps it to 5..3600
  "server_time": 1790844410.1,
  "ctf": {
    "instance_id": "51c9cbca-…",         // changes whenever the device joins a team again
    "event": {"name": "Demo Event", "slug": "demo", "state": "running", "created_at": 1790844300.1,
              "started_at": 1790844318.6, "finished_at": null, "scoreboard_public": true,
              "first_blood_bonus": 10},
    "team": {"id": 3, "name": "PLC Pwners", "banned": false, "score": 1250, "rank": 2, "teams": 14},
    "solved": ["scanning", "opcua"],       // on record for the team, voided solves included
    "catalog_version": "3f9a1c0d2b7e4a55", // changes when the enabled challenges or their flags change
    "announcements": [{"id": 5, "message": "Hint for MITM is out", "created_at": 1790844400.0}],
    "announcement_ids": [2, 5]             // all current ids; drop local ones not listed (deleted)
  }
}
```

- `jobs` holds at most 5 open jobs, oldest first, and stays empty while the device's
  `key_fingerprint` is not the server's. A job is repeated in every answer until its result
  arrives; the client runs each `seq` once.
- `ctf` is `null` while the device is in no event: it never joined, it left, the organiser took it
  out, or its team or event was deleted. A client that was in an event stops sending solves and
  keeps queuing them, because the device is most likely coming back.
- `ctf` names a team the client did not join itself when the organiser put the device there. The
  client adopts it like a join of its own. A new `instance_id` means a new membership.
- `event.created_at` tells a recreated event apart from an older one with the same slug. `rank` is
  `null` while the team has no place on the board (it is disqualified). The standing is at most 2 s
  old.

## 🔒 `POST /ctf/join`

The device joins a team of the event with this join code. If the team name is new in the event, the
call creates the team, provided the event allows self-registration.

```json
{"join_code": "2AD93CWC", "team_name": "PLC Pwners", "team_password": "pass1234"}
```

`201`:

```json
{
  "instance_id": "51c9cbca-…",
  "team": {"id": 3, "name": "PLC Pwners"},
  "event": {"name": "Demo Event", "slug": "demo", "state": "running", "created_at": 1790844300.1,
            "started_at": 1790844318.6, "finished_at": null, "scoreboard_public": true,
            "first_blood_bonus": 10}
}
```

The answer is an **instance**: the device's membership in the team. A device has at most one live
instance, so joining ends any other membership the device had, in this event or another one.

- Unknown join code: `404 invalid_join_code`. Finished event: `409 event_finished`. New team while
  self-registration is off: `403 registration_closed`. Disqualified team: `403 team_banned`.
- If the team already exists, the password must match it (`403 wrong_team_password`). Team names
  are case-insensitive for ASCII letters (SQLite `NOCASE`). Runs of spaces count as one.
- Team names use the Latin script only: ASCII letters, plus accented Latin letters such as `ä`, `é`
  and `ß`, digits and `_ . - ' ! ? ( ) + # & @`, 2 to 40 characters. Anything else is
  `400 invalid_team_name`, which rules out look-alike letters from other scripts.
- A new team name that looks like an existing one on a projector is refused with `409
  team_name_taken`. That covers case (including non-ASCII case, so "ärger Team" next to "Ärger
  Team"), accents, spacing, punctuation, and `0`/`o` or `1`/`l`.
- A **new** team needs a password of 8 to 128 characters that is not a well-known one, not the team
  name, and not one repeated character (`400 weak_team_password`). Joining an existing team needs its
  password, whatever its length.
- One address may create at most 100 new teams per 10 minutes (`429`). Only teams that were actually
  created count, so failed attempts use up no quota.
- A team can have at most 25 live devices (`409 too_many_instances`), and at most 100 devices may
  join it per hour (`429 too_many_instances`).

**Board UID.** When a physical board joins a team in which a device with the same `device_uid` is
live, that device's instance ends: a reflashed SD card makes a new device for the same board. This
happens only **within the team**. The UID is broadcast in the board's SSID, so anyone can claim it,
and it never affects another team. If another team of the event has a live device with the same UID,
the join still succeeds, but it is logged and flagged on the organiser's *Instances* page. A board
replacing its own registration does not count towards the 25.

**Password hashing.** It is deliberately slow, and the server runs at most two at a time. A request
that cannot get a hashing slot within 2 seconds gets `503 busy` and should be retried after a short
pause, which the landing page leaves to the user. Disqualified teams and teams at their cap are
refused before anything is hashed. This keeps a flood of joins from tying up the threads that serve
heartbeats and solves.

**Wrong team passwords** are logged and listed on the organiser's audit page, but they never lock a
team out: a lockout would let a rival on the same NAT address keep a team from joining. Guessing is
bounded by the proxy (8 requests per second per address) and by the hashing budget (about ten per
second for the whole server). That is roughly 35,000 guesses an hour at most, against a password of
at least 8 characters that is not on the common-password list. A burst of wrong guesses is visible
in the audit long before it gets anywhere. Teams that want more margin should use a longer password.

Wrong team passwords also count towards a flood guard per address (`MGMT_RATE_JOIN`, 60 per minute,
then `429`). Successful joins, malformed requests and unknown join codes do not count. The organiser
sees addresses that hit the guard and can clear them.

## 🔒 `DELETE /ctf/join`

The user left the event on the landing page. The device's instance ends; the device stays enrolled.
`204`, also when the device was in no event.

## 🔒 `POST /solves`

Report a solve that the landing page has already verified locally, for the device's team. The call
is idempotent per team and challenge. At most 30 per device and minute.

```json
{"challenge_id": "opcua", "flag": "CybICS(…)", "solved_at": 1790844399.2}
```

A device in no event gets `409 not_in_event`, and one whose team is disqualified `403 team_banned`.
Neither says anything about the solve: keep it queued. `challenge_id` and `flag` must be strings;
anything else gets `400 invalid_input`, which is final for that solve.

A valid request from a device in an event always gets `200`:

```json
{"result": "accepted", "points": 250, "bonus": 25}
```

**Every answer except a 5xx, 401, 403, 429, `409 not_in_event` and a 4xx without this server's JSON
shape is final for that solve.** The client takes the item out of its outbox on any `result` value
and on any other 4xx. A client must treat a `result` value it does not know like `invalid_flag`. New
values may be added in v1, and each must be safe to handle that way.

| `result` | Meaning |
|---|---|
| `accepted` | Counted; `points` holds the value. |
| `duplicate` | The team already has this challenge, possibly from a teammate's device. |
| `invalid_flag` | The flag does not match. An unmodified landing page only forwards flags it validated locally, so this is logged as suspicious. An honest `invalid_flag` means the organiser imported another CybICS version's catalog: the reference client holds the solve and retries when `catalog_version` (which covers ids **and** flags) changes. Every retry is audited. |
| `unknown_challenge` | The id is not in the event's catalog, or the challenge is disabled. Hold the solve and report it again once the heartbeat's `catalog_version` changes. |
| `event_not_running` | The event is in draft, paused or finished. The solve does not count. The client must not resubmit it, with one exception: if the solve was made while the event was running, the client holds it until a heartbeat shows `running` again, and then sends it once more; otherwise it stays held (an organiser can reopen an event finished by mistake). "Made while running" is judged from the client's last heartbeat, so a solve made within one heartbeat interval after a pause also counts. |

`bonus` is the first blood extra: the event's `first_blood_bonus` percent of the points, given to the
first team to solve the challenge, and `0` otherwise. On the scoreboard the bonus belongs to the
first solve that *counts*: if that solve is voided or its team disqualified, the bonus moves to the
next solver.

`solved_at` is the device's own clock (Unix seconds). It is stored for the organiser's information
only, and only if it lies within 90 days before and one day after the server's time; otherwise it
is dropped. Ordering and tie-breaks use the server's receive time.

## 🔒 `GET /challenges`

The enabled challenges of the device's event, without flags. `409 not_in_event` while the device is
in no event.

```json
{"challenges": [{"id": "opcua", "title": "OPC-UA", "category": "⚔️ Security Testing",
                 "points": 250, "type": "offensive"}]}
```

## 🔒 `POST /jobs/<id>/logs`

The log bundle of a `collect_logs` job, as the raw body: gzip, at most 256 KB, `Content-Type:
application/gzip`. `204`, or `404` (no such `collect_logs` job of this device), `400` (not gzip),
`409` (already uploaded), `413` (too large). The server keeps the newest 5 bundles per device.

## 🔒 `DELETE /device`

The user disconnected the installation from the server. The device is retired and its instance, if
any, ends (`204`). Its history stays. The token stops working; connecting again enrols a new device.

The organiser can also retire a device. Its token then gets `401 unauthorized` and its instance
ends. Bringing it back makes the token valid again, but does not rejoin the event.

## `GET /events/<slug>/scoreboard`

Public, but only if the event's scoreboard is public and the event is not a draft; otherwise it
returns `404`. The projector page polls it every 5 s.

It is served from a cache that is at most 2 s old, and not rate limited per address: a limit would
let one participant behind the projector's NAT address blank the projector.

```json
{
  "event": {…},
  "scoreboard": [{"rank": 1, "name": "Red Team", "score": 1450, "solves": 8, "last_solve": 1790844320.9}],
  "recent_solves": [{"team": "Red Team", "challenge": "OPC-UA", "points": 250,
                     "first_blood": true, "bonus": 25, "time": 1790844320.9}],
  "server_time": 1790844330.0
}
```

---

## Jobs

A job is one action from a fixed list, for one device. There is no generic command.
[MGMT_DESIGN.md](MGMT_DESIGN.md#jobs) has the design.

| `action` | `params` | The device |
|---|---|---|
| `identify` | `{"seconds": 5..600}` | shows a banner with its label on the landing page |
| `message` | `{"text": "…"}` (at most 500 characters) | shows the text on the landing page |
| `restart` | `{"service": "all" or a service name}` | restarts CybICS services (`utils/restart.py`) |
| `reset_progress` | `{}` | clears the local CTF progress (`/ctf/reset`) |
| `collect_logs` | `{}` | uploads a log bundle to `/jobs/<id>/logs` |

The server creates a job only for a device that is not retired, has pinned the server's current key
and allows the action. A client runs a job only if all of these hold, and otherwise ignores it (bad
signature, wrong device, old `seq`) or answers `refused` (action not allowed on the device):

1. `signature` is a valid RSA PKCS#1 v1.5 SHA-256 signature, in hex, under the pinned key, over the
   canonical JSON of `{"action", "device", "id", "params", "seq"}`: keys sorted, no spaces,
   non-ASCII escaped (Python `json.dumps(..., sort_keys=True, separators=(",", ":"),
   ensure_ascii=True)`).
2. `device` is its own device id.
3. `seq` is higher than every `seq` it accepted before. That stops replays without a clock.
4. The user allowed `action` on the device.

A job that was not delivered within 24 hours expires. The organiser can cancel an open job; a
device that already received it may still run it, and its result is recorded.

Putting a device into a team is not a job: the organiser changes the membership on the server, and
the device learns it from the `ctf` part of its next heartbeat answer.
