# Architecture

This document describes the CTF part of CybICS-mgmt; the fleet part is in
[MGMT_DESIGN.md](MGMT_DESIGN.md). The CTF server is an **optional** central point for events with
several [CybICS](https://github.com/mniedermaier/CybICS) instances. Each instance may be virtual (the Docker
stack on a participant's laptop) or physical (a Raspberry Pi Zero 2 W board). A CybICS instance never
depends on this server: it validates flags and keeps progress locally, as it always has. Once a
participant enrols it from the landing page, it also reports its team, its status and its solves here,
and the organiser gets a shared scoreboard and an overview of every instance.

```
 participant laptops                     event network / internet                 organiser
┌──────────────────────┐                                                     ┌──────────────────┐
│ CybICS (virtual)     │   POST /api/v1/enroll      (once)                    │ CybICS-mgmt      │
│  landing ── client ──┼──────────────────────────────────────────────────►  │  Flask + SQLite  │
└──────────────────────┘   POST /api/v1/heartbeat   (every 30 s)              │                  │
┌──────────────────────┐   POST /api/v1/solves      (on each local solve)     │  /admin          │
│ CybICS (Pi + PCB)    │                                                      │  /scoreboard/... │
│  landing ── client ──┼── wlan1 (USB dongle) ────────────────────────────►  │                  │
│  wlan0: training AP  │                                                      └──────────────────┘
└──────────────────────┘
```

## What the investigation of CybICS found

The design follows from how CybICS works today. The findings are pinned to CybICS v1.2.3 (`main`,
October 2026).

### The CTF in CybICS

- There are 22 challenges in 6 categories, worth 5,050 points in total. They are defined in
  `software/landing/ctf_config.json`.
- Every challenge has an `id`, `points`, a plaintext `flag` in the form `CybICS(...)`, and an
  optional `type`:
  - offensive (the default)
  - `verify` (4 challenges)
  - `defense` (5 challenges)
- A `verify` or `defense` challenge has no flag for the user to find. The landing page runs a local
  check (`modules/defense_checks/<module>.verify()`) against the instance, and only when it passes
  does it hand out the flag and record the solve.
- Validation is a plain string comparison in `ctf_manager.submit_flag`.
- Progress is one JSON file per instance (`data/ctf_progress.json`): a list of ids and a point total.
  - It has no user, team or instance identity, and no timestamps.
  - No volume is mounted for it, so recreating the container loses it.
- **All flags are identical in every installation.** The training READMEs print them as solutions.
- Nothing in CybICS talks to a central service. Its only outbound HTTP goes to the local AI agent
  container.

### The virtual stack

- Docker Compose runs about 11 services on `172.18.0.0/24`, plus `landing` and `ids` with host
  networking.
- `landing` is Flask 3.1.3 on Python 3.12-alpine, listening on port 80. It runs with `NET_ADMIN`
  and has the Docker socket mounted.
- Images are published multi-arch to Docker Hub as `mniedermaier1337/*`.
- Releases are git tags (`v1.2.3`). The version string appears only in `stm32/src/version.h` and
  `hwio-virtual/hardwareAbstraction.py`.

### The physical device

- It runs Raspberry Pi OS Trixie (arm64) with NetworkManager.
- The onboard `wlan0` serves the training network.
  - In AP mode the SSID is `cybics-<STM32 UID>`, the PSK is `1234567890` and the range is
    `10.0.0.1/24` with `ipv4.method=shared`.
  - In station mode it joins an SSID `cybics`.
  - The STM32 mode button switches between the two, through `hwio-raspberry/hardwareIO.py` calling
    nmcli.
- The hostname is `cybics` on every board.
- The **only per-device identity is the STM32 UID** (12 hex digits). It is read over I²C and already
  shown in the SSID and on the LCD.
- There is no update or phone-home mechanism.

### What follows for the design

| Finding | Consequence |
|---|---|
| Flags are static and published | The server cannot prove a team earned a flag, only that an enrolled instance reported a correct one. Anti-cheat therefore relies on audit and moderation, not cryptography (see [Trust model](#trust-model)). |
| `verify`/`defense` flags are released by a local check | Instances report `(challenge_id, flag)` for every type. One code path covers all 22 challenges, and the server re-checks the flag against its own catalog. |
| `ctf_config.json` is the source of truth | The server imports that file and does not maintain its own challenge list. It stores only a SHA-256 of each flag. |
| The server is optional | All behaviour is opt-in, and the client makes no network calls until it is enrolled. A server outage never affects local play: reports are queued and retried. |
| No identity on the instance | Enrolment issues an instance id and a bearer token. Physical boards also send their STM32 UID, so a reflashed board replaces its old registration. |
| Progress persists in the container layer | A reused Pi may already have solves. The client records a baseline at enrolment and never reports solves older than that. |
| Teams share a laptop or use several | A team has a name and a password. Every instance that enrols with both joins that team, and solves are counted per team. |

## Components

| Path | What it is |
|---|---|
| `server/cybics_mgmt/` | The server: a Flask app factory, a JSON API, an admin UI and a public scoreboard. |
| `server/cybics_mgmt/ctf/` | The CTF part. `logic.py` holds the domain logic (events, catalog, teams, instances, solves, scoring) and has no HTTP code; `api.py`, `admin.py`, `public.py` and `cli.py` attach the CTF routes and commands to the shared blueprints. |
| `server/cybics_mgmt/db.py` | SQLite (WAL) with numbered migrations tracked in `PRAGMA user_version`. |
| `client/cybics_mgmt_client.py` | Reference client to be vendored into CybICS' landing service. It is standard library only. |
| `server/tests/` | pytest suite, including the client against a live HTTP server. |

### Data model

```
events ─┬─ challenges   (imported from ctf_config.json; flag stored as sha256)
        ├─ teams ── instances   (token stored as sha256; kind, STM32 UID, version, last status)
        │     └── solves        (unique per team and challenge; server receive time is authoritative)
        ├─ submissions          (audit log of every report, including wrong ones)
        └─ announcements
```

### Event lifecycle

`draft → running ⇄ paused → finished`, and `finished → running` to reopen an event finished by
mistake. No other transitions are allowed; in particular, nothing goes back to `draft`. The admin UI
only offers the allowed transitions and asks for confirmation.

- Instances can enrol in every state except `finished`. Participants can therefore join before the
  start, and the landing page shows "waiting for start".
- Solves count only while the event is `running`.
- A solve counts if the server *receives* it while the event is `running`. The server cannot judge
  when a solve really happened, because the instance controls its clock.
  - A report that arrives in any other state does not count, and the client does not resubmit it.
    In practice, work done during a pause does not count.
  - Exception: a solve made while the event was running whose report only arrived during a pause is
    held and resent (see the sync protocol).
  - Conversely, a solve made before the start but held up in an outbox until after the start does
    count. That only happens with an instance that was offline across the start.
- An event cannot be set to `running` while its catalog is empty, because every solve would then be
  answered `unknown_challenge`.
- While an event is a draft, its scoreboard stays private, even if it is marked public. Team names
  do not leak before the start.

### Scoring

- Each challenge is worth its static points, which the organiser can override per event.
- Ties are broken by who reached the score first, using the server's receive time. Instance clocks
  are recorded for information but never trusted.
- A challenge disabled mid-event keeps the points already awarded for it.
- Disqualified teams drop off the board, and so do solves the organiser voided.
- First blood goes to the first solve that counts. Solves by disqualified teams and voided solves
  are skipped.
- Optional **first blood bonus**, per event and off by default: the first solve that counts earns
  that percentage of the challenge's points on top. Because the bonus is computed from the current
  solves, it follows moderation: if that solve is voided, the next solver gets the bonus.

### Sync protocol

Every report must survive the server being down, so the client keeps its state in a file:

1. **Report.** After a successful local `/ctf/submit` or `/ctf/verify`, landing calls
   `client.report_solve(id, flag)`. The solve goes into a persistent outbox and the sender thread
   wakes up. This call never blocks or fails the local submission.
2. **Flush.** The client posts each outbox item to `/solves`. Every answer takes the item out of the
   outbox:
   - `accepted` or `duplicate` means done.
   - `unknown_challenge` or `invalid_flag` means the item is *held* until the catalog changes (see
     step 3). The landing page validated the flag locally, so either answer means the server's
     catalog disagrees with the instance's: imported late, a challenge disabled for a while, a newer
     CybICS with extra challenges, or the wrong CybICS version imported. `catalog_version` covers ids
     and flags, so fixing the import releases the held solves.
   - `event_not_running` for a solve made while the event was running means the solve is held until
     the next heartbeat decides:
     - `running` sends it again;
     - `paused` or `finished` keeps holding it, because an organiser can reopen an event finished
       by mistake.
   - Anything else is remembered as rejected and never reported again:
     `event_not_running` for a solve made during a pause or after the end, a 4xx for this solve, or
     a result value this client does not know yet.

   Only transport errors, 5xx, 401, 403, 429, and 4xx answers that are not this server's JSON (a
   reverse proxy's error page) keep an item queued. Retries back off to at most 5 minutes.
3. **Heartbeat** every 30 s. It sends the status: version, mode, service health and local solves.
   The server answers with:
   - the event state;
   - the team's score and rank;
   - the challenges the server has on record for the team, voided ones included;
   - a `catalog_version`, a fingerprint of the enabled challenges. When it changes, solves held as
     `unknown_challenge` get another try. When the event state is `running` again, solves held during
     a pause do too;
   - new announcements.
4. **Reconcile.** While the event is running, any local solve that is unknown to the server is queued
   again. This excludes the baseline, rejected and held solves, and solves already in the outbox. It
   covers a lost outbox and solves made while the instance was offline. Voided solves stay on the
   team's record, so reconciliation does not bring them back.
5. **Revocation and re-enrolment.** If the token comes back `401` (revoked, or the event was
   deleted), the client disables itself until the user enrols again, but keeps queuing local solves.
   - Enrolling again with the same server and event carries over the outbox, the baseline and every
     held or rejected decision, so nothing is lost or reported twice. "Same event" means the same
     slug **and** creation time. An event deleted and recreated under the old slug starts fresh.
   - Solves made while the user had *left* on purpose are treated like solves from before
     enrolment, and are not reported. A `403 team_banned` does not disable it, because the
   organiser can reinstate the team; the client keeps retrying with backoff.
6. **Stale answers.** Each request remembers the token it was sent with. An answer that arrives
   after the user left or re-enrolled is discarded, so it cannot touch the new enrolment.
7. **Failure isolation.** `report_solve` never raises, and the sender thread catches every error and
   backs off. Truncated or non-JSON answers count as "unreachable". Whatever goes wrong, local play
   is unaffected.

## Trust model

Assume participants have full control of their instance. On a virtual instance they literally have
root, and the flags are in the training material. The server's job is to make honest play the easy
path and to make dishonest play visible:

- **Tokens.** A solve has to come from an enrolled, non-revoked instance of a non-banned team.
- **Team passwords.** New teams need at least 8 characters. Wrong passwords are logged and listed in
  the audit, where repeated failures show up as an attempt to join someone else's team. They never
  lock the team out.
  - Guessing is bounded by the proxy (8 enrolments per second per address) and by the hashing
    budget (about ten per second server-wide), which comes to roughly 35,000 guesses an hour.
  - Against 8+ characters with common passwords refused, that is slow, and it is visible in the
    audit.
- **Enrolment cost.** Enrolment is the only request that costs real CPU (scrypt). Several layers
  keep a flood of enrolments, even successful ones into the attacker's own team, from stalling
  heartbeats and solves:
  - nginx queues enrolments at 8 per second per address;
  - a request waits at most 2 s for one of the two hashing slots, then gets `503 busy`;
  - a team has at most 25 active instances;
  - disqualified teams are refused before anything is hashed.

  `tools/slowloris_check.py --join-code` measures this, and CI runs it.
- **Shared addresses.** A whole classroom often shares one NAT address with the projector and the
  organiser. Any limit that counts failures per address can then be tripped by one participant for
  everybody, so:
  - no security property depends on a per-address limit;
  - the remaining limits are generous flood guards that count only provably bad requests (failed
    enrolments, unknown tokens, failed admin logins, teams actually created). Valid tokens are never
    limited;
  - the organiser sees tripped limits on the *Events* page and clears them with one click;
  - the admin login has a way in that no participant can block: a one-time login link from the
    server's command line;
  - the public scoreboard is cached, not limited;
  - nginx has no per-address connection cap at all. It drops half-sent headers and stalled bodies
    after 5 s, keeps API bodies at 64 KB, and holds tens of thousands of connections in a fixed two
    workers within its memory limit. One participant holding a thousand slow uploads open does not
    slow down anybody's heartbeats, not even from the same address; `tools/slowloris_check.py`
    measures exactly that;
  - the only per-address rule in nginx queues enrolments (8 per second, short burst queue). It slows
    a flood and never refuses heartbeats or solves;
  - against raw connection floods from the internet, the README shows a generous host firewall
    cap, with the caveat that it also applies per NAT address.
- **Audit log.** Every submission is recorded with its result, source address and team name. The
  record survives deleting the team. An unmodified landing page checks flags locally before
  forwarding them, so **a wrong flag means someone is calling the API directly**. The admin UI counts
  wrong flags per team and lists them on the *Solves & audit* page.
  - Unknown challenge ids are logged but not flagged: an honest instance running a newer CybICS
    sends them too.
- **Timing.** The server's receive time decides order and ties. Solves stamped by the instance's own
  clock are shown for comparison only.
- **Moderation.** The organiser can:
  - void a single solve, which scores nothing but stays on the record, and restore it later;
  - revoke an instance;
  - disqualify a team.

  Every organiser action, from the web UI or the command line, is stored in an `admin_log` table and
  shown on the event's *Log* page, with a CSV export. It is also logged to stderr.
- **Rate limits.**
  - Enrolment is limited per IP.
  - Heartbeats and solves are limited per instance.
  - Admin login is limited per IP.

What the server deliberately does **not** attempt is to make flags secret. That would need per-instance
flags. One option: derive them from an event secret pushed at enrolment, e.g.
`CybICS(HMAC(event_secret, instance_id, challenge)[:12])`. Every flag source in CybICS would have to
generate them: the firmware, OpenPLC's database, the FUXA project, the IDS, OPC-UA and S7. That is a
large change and stays a possible later step. The API is versioned (`/api/v1`), so it can be added
without breaking existing clients.

### Physical boards are more trustworthy, not trusted

A physical board reports its STM32 UID. That gives the organiser a stable identity per board: it
survives an SD card reflash, and a re-enrolment within the team replaces the old registration.

A UID is not secret: it is broadcast in the board's SSID and can be claimed by anyone. So a
re-enrolment only ever revokes instances of the *same* team. A UID that shows up in two teams is
logged and flagged on the *Instances* page, and never acted on automatically. The UID identifies a
board; it does not authenticate one.

## Deployment

- **Server**: `docker compose up -d` starts nginx in front of gunicorn, with one volume (`/data`:
  database, secret key, generated admin password).
  - nginx reads each request completely, with 5 s timeouts, before gunicorn sees it. Slow or idle
    connections cost only nginx, so they cannot starve gunicorn's thread pool;
    `tools/slowloris_check.py` checks this in CI.
  - Only nginx publishes a port. gunicorn accepts forwarded headers from nginx's fixed address alone.
  - Both containers run read-only, as non-root users, with all capabilities dropped and
    `no-new-privileges` set.
  - Admin sessions are signed cookies, and each one is also recorded server side. Logging out ends
    the session in the database, so a copied cookie stops working too.
  - `flask --app cybics_mgmt backup <path>` writes a consistent copy of the database with
    `VACUUM INTO`, and is safe while the server runs. Copying the `.sqlite` file alone can miss
    writes that are still in the WAL.
  - gunicorn runs with 1 worker and 16 threads.
  - SQLite and the in-memory rate limiter both want a single process, and that is ample for a few
    hundred instances heartbeating every 30 s, which is about 10 requests per second.
- **TLS**: terminate it in an outer proxy (Caddy, Traefik) in front of the bundled nginx. Then set:
  - `MGMT_BIND=127.0.0.1`, so the outer proxy is the only way in;
  - `MGMT_OUTER_PROXY=<its address as nginx sees it>`, so nginx (and with it the app and the
    enrolment queue) takes the client address and `https` from that proxy and from nobody else;
  - `MGMT_SECURE_COOKIES=1`.
  - Plain HTTP is acceptable on an isolated event Wi-Fi.
  - The client accepts a private CA file for a self-signed server.
- **Event network for physical boards**: see [CYBICS_INTEGRATION.md](CYBICS_INTEGRATION.md#physical-device-second-wi-fi-interface).
