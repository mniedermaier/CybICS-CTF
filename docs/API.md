# API v1

Base path: `/api/v1`. All request and response bodies are JSON.

- **Authentication.** Endpoints marked 🔒 need `Authorization: Bearer <token>`, using the token
  returned by `/enroll`. Endpoints marked 🔑 need the device token returned by `/fleet/enroll`
  instead.
- **Errors.** Every error has the same shape. Show `message` to the user unchanged:

```json
{"error": {"code": "wrong_team_password", "message": "Wrong password for this team."}}
```

| HTTP | Meaning for the client |
|---|---|
| 400 | Bad input; see `code`. A field of the wrong JSON type is `invalid_input`. |
| 401 `unauthorized` | Token unknown or revoked. Stop syncing and ask the user to enrol again. Repeated *unknown* tokens from one address are rate limited; a valid token is never limited by that, so garbage from a shared NAT address cannot stall honest instances behind it. |
| 403 | `wrong_team_password`, `registration_closed`, `team_banned`, `invalid_device_token`, `code_disabled` (fleet). `team_banned` is not permanent: the organiser can reinstate the team, so keep retrying with backoff. |
| 404 | `invalid_join_code`, `invalid_code` (fleet), `not_found`. |
| 4xx without this JSON shape | Not from this server (a reverse proxy's error page while the backend restarts). Treat it like a 5xx: keep queued data and retry. |
| 409 | `event_finished`, `team_name_taken`, `too_many_instances` (25 active per team). |
| 503 `busy` | No password-hashing slot within 2 s, or the team changed during the request. Retry after a few seconds. |
| 413 | Body larger than 1 MB. |
| 429 `rate_limited` | Back off. Also `too_many_instances` when a team enrolled more than 100 instances in an hour. |
| 5xx / no answer | Transient. Keep queued data and retry later. |

---

## `GET /info`

Unauthenticated. The landing page's **Test connection** button calls this.

```json
{"service": "cybics-ctf", "product": "cybics-mgmt", "features": ["ctf", "fleet"], "name": "CybICS-mgmt",
 "version": "0.1.0", "api_version": 1, "server_time": 1790844304.29}
```

- `service` is `"cybics-ctf"` and stays so in v1, also after the rename to CybICS-mgmt: deployed
  clients compare it to tell this server from any other.
- `product` and `features` were added with the rename. `features` lists what the server offers
  beyond the v1 CTF endpoints, so newer clients can check before they use it. Clients must ignore
  values they do not know.

## `POST /enroll`

Failed enrolments count towards a flood guard per address (see below). The proxy also holds
enrolment requests to 8 per second per address and queues bursts instead of refusing them.

- If the team name is new in the event, the call creates the team, provided the event allows
  self-registration.
- If the team already exists, the password must match it. Team names are case-insensitive for ASCII
  letters (SQLite `NOCASE`). Runs of spaces count as one.
- Team names use the Latin script only: ASCII letters, plus accented Latin letters such as `ä`, `é`
  and `ß`, digits and `_ . - ' ! ? ( ) + # & @`. Anything else is `400 invalid_team_name`, which
  rules out look-alike letters from other scripts.
- One address may create at most 100 new teams per 10 minutes (`429` after that). Only teams that
  were actually created count, so failed attempts use up no quota.
- A new team name that looks like an existing one on a projector is refused with `409
  team_name_taken`. That covers case (including non-ASCII case, so "ärger Team" next to "Ärger
  Team"), accents, spacing, punctuation, and `0`/`o` or `1`/`l`.

```json
{
  "join_code": "2AD93CWC",
  "team_name": "PLC Pwners",
  "team_password": "pass1234",
  "instance": {
    "kind": "physical",               // "virtual" | "physical"
    "device_uid": "0042001a3133",     // STM32 UID, hex; required for physical
    "hostname": "cybics",
    "cybics_version": "1.2.3",
    "mode": "full"                    // cybics.sh --mode, if known
  }
}
```

`201`:

```json
{
  "instance_id": "51c9cbca-…",
  "token": "…",                       // returned only once; the server keeps a hash
  "team": {"id": 3, "name": "PLC Pwners"},
  "event": {"name": "Demo Event", "slug": "demo", "state": "running", "created_at": 1790844300.1,
            "started_at": 1790844318.6, "finished_at": null, "scoreboard_public": true},
  "heartbeat_interval": 30
}
```

Optionally, a client that is also enrolled in the fleet sends `"device_token": "…"`, the token from
`/fleet/enroll`. The instance then belongs to that device. An unknown or retired device token is
`403 invalid_device_token`. Without the field, the server creates a *legacy* device for the instance,
which the organiser sees in the fleet with what the CTF heartbeat reports.

When a physical board re-enrols with the same `device_uid` **in the same team**, its previous
registration is revoked. The UID is broadcast in the board's SSID, so anyone can claim it, and it is
never allowed to affect another team. If another team already has a live instance with the same UID,
the enrolment still succeeds, but it is logged and flagged on the organiser's *Instances* page.
`device_uid` is ignored for virtual instances.

A **new** team needs a password of at least 8 characters that is not a well-known one, not the team
name, and not one repeated character (`400 weak_team_password`). Joining an existing team needs its
password, whatever its length.

A team can have at most 25 active instances (`409 too_many_instances`). A board re-enrolling with a
UID already active in its team replaces that instance and does not count.

Password hashing is deliberately slow, and the server runs at most two at a time. A request that
cannot get a hashing slot within 2 seconds gets `503 busy` and should be retried after a short
pause, which the landing page leaves to the user. This keeps a flood of enrolments from tying up the
threads that serve heartbeats and solves.

Wrong team passwords are logged and listed on the organiser's audit page, but they never lock a team
out: a lockout would let a rival on the same NAT address keep a team from enrolling. Guessing is
bounded by the proxy (8 enrolments per second per address) and by the hashing budget (about ten
per second for the whole server). That is roughly 35,000 guesses an hour at most, against a password
of at least 8 characters that is not on the common-password list. A wrong guess burst is visible in
the audit long before it gets anywhere. Teams that want more margin should use a longer password.

Failed enrolments count towards a flood guard per address (60 per minute, then `429`). Successful
enrolments do not count. The organiser sees addresses that hit the guard and can clear them.

## 🔒 `POST /heartbeat`

Send every `heartbeat_interval` seconds. Everything in `status` is optional. It is stored as-is,
up to 16 KB, and shown to the organiser. If a request carries no `status`, the previous status is
kept.

```json
{
  "status": {
    "cybics_version": "1.2.3",
    "mode": "full",
    "services": {"openplc": true, "fuxa": true, "opcua": true, "s7com": false},
    "local_solved": ["scanning", "opcua"]
  },
  "announcements_after": 4              // id of the last announcement already shown
}
```

`200`:

```json
{
  "event": {"name": "Demo Event", "state": "running", …},
  "team": {"id": 3, "name": "PLC Pwners", "score": 1250, "rank": 2, "teams": 14},
  "solved": ["scanning", "opcua"],       // on record for the team, voided solves included
  "catalog_version": "3f9a1c0d2b7e4a55", // changes when the enabled challenges change
  "announcements": [{"id": 5, "message": "Hint for MITM is out", "created_at": 1790844400.0}],
  "announcement_ids": [2, 5],            // all current ids; drop local ones not listed (deleted)
  "heartbeat_interval": 30,              // the client clamps it to 5..3600
  "server_time": 1790844410.1
}
```

## 🔒 `POST /solves`

Report a solve that the landing page has already verified locally. The call is idempotent per team
and challenge. `challenge_id` and `flag` must be strings; anything else gets `400 invalid_input`,
which is also final for that solve.

```json
{"challenge_id": "opcua", "flag": "CybICS(…)", "solved_at": 1790844399.2}
```

A valid request always gets `200`, and every `result` takes the item out of the client's outbox. A
client must treat a `result` value it does not know like `invalid_flag`: it leaves the outbox and is
not reported again until `catalog_version` changes (see below). New values may be added in v1, and
each must be safe to handle that way.

| `result` | Meaning |
|---|---|
| `accepted` | Counted; `points` holds the value. |
| `duplicate` | The team already has this challenge, possibly from a teammate's instance. |
| `invalid_flag` | The flag does not match. This never happens with an unmodified landing page, and it is logged as suspicious. |
| `unknown_challenge` | The id is not in the event's catalog, or the challenge is disabled. Hold the solve and report it again once the heartbeat's `catalog_version` changes. |
| *(also for `invalid_flag`)* | A landing page only forwards flags it validated locally, so an honest `invalid_flag` means the organiser imported another CybICS version's catalog. The reference client holds those solves too, and retries when `catalog_version` (which covers ids **and** flags) changes. Every retry is audited. |
| `event_not_running` | The event is in draft, paused or finished. The solve does not count. The client must not resubmit it, with one exception: if the solve was made while the event was running, the client holds it until the next heartbeat. If that heartbeat shows `running`, the solve is sent again; otherwise it stays held (an organiser can reopen an event finished by mistake). "Made while running" is judged from the client's last heartbeat, so a solve made within one heartbeat interval after a pause also counts. |

```json
{"result": "accepted", "points": 250, "bonus": 25}
```

`bonus` is the first blood extra: the event's `first_blood_bonus` percent of the points, given to the
first team to solve the challenge, and `0` otherwise. On the scoreboard the bonus belongs to the
first solve that *counts*: if that solve is voided or its team disqualified, the bonus moves to the
next solver.

`solved_at` is the instance's own clock (Unix seconds). It is stored for the organiser's information
only, and only if it lies within 90 days before and one day after the server's time; otherwise it
is dropped. Ordering and tie-breaks use the server's receive time.

## 🔒 `GET /challenges`

The event's enabled challenges, without flags.

```json
{"challenges": [{"id": "opcua", "title": "OPC-UA", "category": "⚔️ Security Testing",
                 "points": 250, "type": "offensive"}]}
```

## 🔒 `DELETE /instance`

The user switched the central server off. The call revokes the token and returns `204`.

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

# Fleet

The fleet endpoints live under `/api/v1/fleet/` and were added with CybICS-mgmt (`"fleet"` in the
`features` of `/info`). A device is one CybICS installation; [MGMT_DESIGN.md](MGMT_DESIGN.md) has the
design. Deployed CybICS releases do not call them.

## `POST /fleet/enroll`

Enrols a device. `code` is an enrolment code from the organiser's *Fleet → Groups & codes* page, or
the join code of an event that is not finished. A device that enrols with an enrolment code joins
that code's group. The proxy queues these requests together with `/enroll`.

```json
{
  "code": "7KQ2MWXA",
  "label": "Board 7",                 // optional, at most 40 characters; the organiser can change it
  "device": {
    "kind": "physical",               // "virtual" | "physical"
    "device_uid": "0042001a3133",     // STM32 UID, hex; required for physical
    "hostname": "cybics",
    "cybics_version": "1.2.4",
    "mode": "full"
  }
}
```

`201`:

```json
{
  "device_id": "0b6f…",
  "token": "…",                       // returned only once; the server keeps a hash
  "device": {"id": "0b6f…", "label": "Board 7", "group": "Room 2"},
  "heartbeat_interval": 30
}
```

- Unknown code: `404 invalid_code`; disabled code: `403 code_disabled`; malformed device:
  `400 invalid_device`.
- Flood guards per address, both shown on the organiser's *Events* page with a button to clear them:
  60 unknown codes per minute, and 100 new devices per 10 minutes. Only devices actually created
  count.
- The board UID is never used to authenticate or to merge devices. It is broadcast in the SSID.

## 🔑 `POST /fleet/heartbeat`

Every `heartbeat_interval` seconds. `status` is stored as the device's last status, under the same
limits as the CTF heartbeat (16 KB, nesting depth 8; anything larger or deeper is replaced by an
error note). A heartbeat without `status` keeps the previous one. `cybics_version`, `mode` and
`hostname` in the status update the device's columns.

```json
{
  "status": {
    "cybics_version": "1.2.4",
    "mode": "full",
    "hostname": "cybics",
    "services": {"openplc": true, "fuxa": true, "hwio": false}
  }
}
```

`200`:

```json
{"device": {"id": "0b6f…", "label": "Board 7", "group": "Room 2"}, "heartbeat_interval": 30,
 "server_time": 1790844330.0}
```

A retired device gets `401 unauthorized`, like an unknown token. The organiser can bring it back,
and the same token then works again.

## 🔑 `DELETE /fleet/device`

The user switched fleet management off on the device. The device is retired (`204`); its history
stays.
