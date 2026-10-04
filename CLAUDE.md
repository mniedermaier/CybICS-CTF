# CLAUDE.md

Guidance for Claude Code and other AI assistants working in this repository.

CybICS-mgmt (called CybICS-CTF until October 2026) is the **optional** central server for
[CybICS](https://github.com/mniedermaier/CybICS), the open-source ICS security training platform. It
runs CTF events and manages the fleet of CybICS installations (`docs/MGMT_DESIGN.md`: decisions,
phases and the fleet invariants). It ships together with the CybICS release that replaces v1.2.4, so
there is no compatibility with earlier clients. Virtual CybICS installations (Docker on a laptop) and
physical ones (a Raspberry Pi Zero 2 W board with a USB Wi-Fi dongle as uplink) enrol once from their
landing page and become a **device**, the only identity on the server. A device reports its status,
takes signed jobs, and, once it joins a team in an event, reports the team's solves to a shared
scoreboard. Read `docs/ARCHITECTURE.md` (the CTF part and the device identity) and
`docs/MGMT_DESIGN.md` (the fleet part) before changing behaviour; they record the investigation of
CybICS that the design is based on.

## Language

Everything that lands in git or on GitHub is written in **English**: code, comments, UI text,
documentation, commit messages, branch names, PR titles and bodies, issues and review comments.
Reply to the user in whatever language they write, but never carry that language into a git artefact.
If the user hands you text in another language to put into the repo, translate it.

## Commits, branches and pull requests

Same conventions as CybICS. Commits follow **Conventional Commits**: `<type>(<scope>): <subject>`.

- Types: `feat`, `fix`, `docs`, `test`, `ci`, `build`, `refactor`, `perf`, `chore`.
- Scopes: `server`, `api`, `admin`, `ui`, `client`, `docker`, `docs`. Omit the scope when a change
  spans several of them.
- Subject: imperative, lower-case first letter, no trailing period, at most 72 characters. A breaking
  change gets `!` after the scope and a `BREAKING CHANGE:` footer.
- Body: explain *why*, not what the diff shows, and state what was verified and how.
- Keep the attribution trailers the tooling adds.

Branches are `feature/<topic>`, `fix/<topic>`, `docs/<topic>` and `ci/<topic>`. Work reaches `main`
through a PR. A PR description has three sections: **Cause**, **Fix**, **Verified**.

Never stage `server/data/`, `*.sqlite`, `.env` or anything holding a real admin password or token.

## Repository map

- `server/cybics_mgmt/`: the Flask app.
  - `__init__.py`: app factory and configuration (`MGMT_*` environment variables, read through
    `env()`).
  - `api.py`: the `/api/v1` blueprint, `/info` and what every endpoint shares (`json_body`,
    `rate_limit`, the error format).
  - `admin.py`: the `/admin` blueprint, login, sessions, `LOCKOUTS` and `csv_response`.
  - `public.py`: the start page, `/healthz` and `/favicon.ico`.
  - `errors.py`: `MgmtError`, the base of every error a caller can fix (`ctf.CTFError` is one).
  - `device_input.py`: checks for what installations send about themselves (identity, status),
    shared by both parts.
  - `security.py`: tokens, hashing, the rate limiter, admin password and session, CSRF.
  - `host.py`: requests to the host on the Raspberry Pi image (the `pi` password), through
    `MGMT_HOST_DIR`; the image's root service `cybics-mgmt-host` applies them.
  - `db.py`: SQLite and migrations.
  - `views.py`: template filters, error pages and security headers.
  - `cli.py`: `flask --app cybics_mgmt ...` commands (backup, login-link).
  - `ctf/`: the CTF part. Its modules attach routes and commands to the shared blueprints and CLI, so
    endpoint names stay `api.*`, `admin.*` and `public.*`.
    - `logic.py`: all CTF domain logic (events, catalog, teams, instances, solves, scoring). It has
      no request handling, and every function takes the DB connection. Code imports it as
      `from .ctf import logic as ctf`.
    - `api.py` (`/ctf/join`, `/solves`, `/challenges`, the scoreboard, and the `ctf` part of the
      heartbeat answer through `api.HEARTBEAT_PARTS`), `admin.py` (also the organiser putting a
      device into a team), `public.py` (the scoreboard), `cli.py` (event commands).
  - `fleet/`: the devices and the fleet (devices, groups, enrolment codes, jobs), built the same
    way: `logic.py` (never imports the CTF part), `jobs.py` (the allow-listed actions, signing and
    delivery), `signing.py` (the RSA key in `/data/fleet_signing_key.pem`, created on first use),
    `api.py` (`/enroll`, `/heartbeat`, `/jobs/<id>/logs`, `DELETE /device`, and `authenticate()`
    for every device call), `admin.py` (`/admin/fleet/*`, endpoints `admin.fleet_*`).
- `server/tests/`: pytest. `test_client.py` runs the reference client's CTF sync against a live
  server, `test_fleet_client.py` its device side and jobs.
- `client/cybics_mgmt_client.py`: the reference client that CybICS' landing service vendors: one
  class, `MgmtClient` (device, CTF sync, jobs).
- `docs/`: `ARCHITECTURE.md` (CTF design and trust model), `MGMT_DESIGN.md` (fleet design and plan),
  `API.md` (the contract) and `CYBICS_INTEGRATION.md` (what has to change on the CybICS side).
- `docker-compose.yml`, `server/Dockerfile` and `proxy/nginx.conf`: the deployment. nginx (the only
  published port) runs in front of gunicorn, with the `/data` volume.
- `tools/slowloris_check.py`: proves that slow clients cannot starve gunicorn. CI runs it.
- `image/`: the Raspberry Pi image (Pi 3, 4, 5, Zero 2 W). `build.sh` builds both containers for
  arm64 and runs pi-gen (submodule `image/pi-gen`, branch `arm64`, pinned like CybICS'). The stage
  `image/stage-mgmt/` ships the `cybics-mgmt` access point (10.42.0.1/24), the compose stack on port
  80 (generated from `docker-compose.yml`, so there is one source) and `cybics-mgmt.txt` on the boot
  partition, applied at every boot by `cybics-mgmt-config`. `.github/workflows/rpi-image.yml` builds it
  on tags (and attaches it to the release) and on pull requests that change `image/`.
- `ruff.toml`: lint configuration, with `target-version = py39` for the client.

## Running and testing

```bash
cd server && pip install -r requirements-dev.txt && ruff check .. && pytest   # needs Python 3.12
MGMT_ADMIN_PASSWORD=... docker compose up -d --build          # http://localhost:8000
python3 tools/slowloris_check.py localhost 8000              # against the running stack
```

If the host has no usable venv, run the suite in the target image instead:

```bash
docker run --rm -v "$PWD:/src" -w /src/server python:3.12-alpine \
  sh -c "pip install -q -r requirements-dev.txt && python -m pytest"
```

That container writes root-owned `__pycache__` and `.pytest_cache` into the tree. Remove them the
same way: `docker run --rm -v "$PWD:/src" python:3.12-alpine sh -c 'cd /src && rm -rf ...'`.

- Run the whole suite before every PR. CI runs one workflow per README badge in
  `.github/workflows/`: `pytest.yml` (ruff, tests, coverage of at least 90 %), `client.yml` (the
  client tests on Python 3.9, the oldest version the client supports), `compose.yml` (the stack
  through `docker compose` with the full hardening: read-only root, no capabilities), `codeql.yml`
  and `trufflehog.yaml`. When adding a workflow, add its badge to the README. A command that writes
  outside `/data` or `/tmp` fails there, and so should your local check.
- For UI changes, check both themes in a browser. `?theme=light` and `?theme=dark` force a theme
  without saving it, which works with `google-chrome --headless --screenshot`.

## Invariants: do not break these

- **The server is optional.** CybICS must work without it. The client makes no network call until
  the user enrols, never blocks or fails a local submission, and queues reports through outages.
  Any feature that would make CybICS depend on the server is out of scope.
- **The device is the only identity.** A device is one CybICS installation; its token authenticates
  every API call, the CTF ones included. An instance is a device's membership in a team
  (`joined_by` `device` or `organiser`), and a device has at most one live instance.
- **Devices are retired, never deleted.** A device outlives events: every instance belongs to a
  device, and deleting an event or a team removes its instances, never its devices. Retiring or
  disconnecting a device ends its instance.
- **Device input is display data.** Fleet telemetry goes through `device_input.py`, like instance
  status, and never decides anything. The board UID only *suggests* that two devices are one board.
- **Fleet organiser actions are audited with an action starting with `fleet_`.** The fleet log
  lists them all. Most have no event and stay off the events page's login list; putting a device
  into a team (`fleet_device_assign`) carries that event, so it is on the event's log as well.
- **Jobs are allow-listed, signed, sequenced actions.** `jobs.ACTIONS` is the whole list, each with
  a parameter check; there is no shell, file write or generic command, and a new action needs a new
  client release. A job is created only for a device that allows the action and pinned the server's
  key, is signed over its canonical JSON, and carries a `seq` that increases per device. Nothing a
  job carries may be valid beyond the device: no tokens, no shared passwords. Putting a device into a
  team is therefore not a job: the organiser changes it on the server, and the heartbeat answer
  carries it to the device.
- **The client executes nothing itself.** `MgmtClient` verifies a job (pinned key, own device id,
  higher `seq`, action allowed on the device) and calls a handler landing registered; every action
  is off after enrolment. It never raises into landing. Keep the signature check in plain standard
  library (`verify_signature`), and never parse the decrypted padding.
- **The signing key is never replaced silently.** Every enrolled device pinned it; an unreadable
  key file stops jobs with an error instead.
- **The API is a contract with CybICS releases.** `/api/v1` is the contract with every CybICS
  release from the one that replaces v1.2.4 on. Changes under `/api/v1` may only *add* fields or
  endpoints. Renaming, removing or changing the meaning of anything needs `/api/v2`, served
  alongside v1. Update `docs/API.md` in the same change.
- **Every `/solves` answer except 5xx, 401, 403, 429 and `409 not_in_event` is final for that
  solve.** The client takes the item out of the outbox on any `result` value, including ones it does
  not know, and on any other 4xx that carries this server's JSON error shape (a proxy's error page
  keeps it queued).
  - `409 not_in_event` (and `"ctf": null` in the heartbeat) means the device is out of its event:
    the client marks itself removed and keeps queuing. `401` means the device was retired.
  - Unknown values are treated like `invalid_flag`. So a new `result` value in v1 must be safe to
    treat that way.
  - Final does not always mean dropped: `unknown_challenge` and `invalid_flag` are held and retried
    once the heartbeat's `catalog_version` changes, and `event_not_running` for a solve made while
    the event ran is held until it runs again.
- **Moderation never deletes evidence.** Removing a solve sets `solves.voided`; the solve stays in
  the team's `solved` list, so clients do not report it again. Deleting a team keeps its
  `submissions` rows (`team_id` becomes NULL, and `team_name` is a snapshot). Keep it that way.
- **The client never takes landing down.** `report_solve` never raises, `_http` turns every
  transport problem into `MgmtClientError`, and the sender and job threads catch everything and
  back off.
- **A board UID never acts across teams.** It is broadcast in the SSID. A board joining a team in
  which its UID is live replaces that instance, only within the team; a UID seen in two teams is
  logged and flagged, never acted on. It never authenticates and never merges devices.
- **Event state changes follow `ctf.TRANSITIONS`.** Nothing returns to `draft`.
- **Client answers are checked against the enrolment.** Every request remembers the token, and for
  the CTF the instance id, it was sent with. An answer for a token or an instance that is no longer
  current is discarded (`_current`). Keep that check around any new state the client updates from a
  response.
- **Device input never causes a 500.** String fields go through `ctf._text()` or `device_input.py`;
  numbers from devices are clamped or dropped (`_client_time`, `announcements_after`). The template
  filters `time` and `ago` return `-` for anything they cannot render.
- **The client stays a single file using only the standard library, on Python 3.9 or later.** It is
  copied into CybICS (`software/landing/modules/cybics_mgmt.py`), which ships with no extra
  dependencies for it. Keep the copy there in sync when the client changes.
- **Flags never appear in plaintext** in the database, the UI, the API or the logs. The catalog
  stores SHA-256 only, and tests assert that the admin pages and `/challenges` do not leak flags.
- **Tokens are stored hashed.** They are returned exactly once, at enrolment.
- **Migrations in `db.py` are append-only.** Never edit a migration that has shipped; add a new one.
- **One gunicorn worker.** The rate limiter lives in process memory and SQLite serialises writes
  anyway. Scale with threads, not workers.
- **Every organiser action is logged** through `security.audit()`, which writes the `admin_log` table
  and a WARNING log line. A new admin route or CLI command that changes state must call it (CLI
  commands pass `actor="cli"`).
- **Secrets are never empty.** `_persistent_secret` replaces an empty or short secret key file, and
  `check_admin_password` refuses an empty password. Without `MGMT_ADMIN_PASSWORD`, nobody is admin
  until the first visit sets a password (`admin_setup_needed`); it is stored as a scrypt hash only,
  and a change ends every other session.
- **The server never acts on its host by itself.** On the Raspberry Pi image it may only drop a
  request into `MGMT_HOST_DIR` (a tmpfs); `cybics-mgmt-host` accepts nothing but a new password for
  `pi`, deletes the request first and reports in `status.json`. The containers stay unprivileged.
- **Slow hashing stays outside the write lock, and never queues for long.** Team passwords are
  hashed and checked before `transaction()`, through `security.hash_password`/`verify_password`.
  Those wait at most `HASH_WAIT` for one of two slots, then raise `HashingBusy` (503). Cheap refusals
  (banned team, instance cap) come before any hashing. Enrolment hashes nothing.
- **Team names are Latin script only** (`ctf.TEAM_NAME_RE`). Look-alike letters from other scripts
  cannot be used, and `team_name_skeleton` catches the rest.
- **The containers stay hardened.** Both run as non-root users with read-only root filesystems
  (`/tmp` is a tmpfs), all capabilities dropped and `no-new-privileges`. Only `/data` is writable.
- **gunicorn is never published directly.** Requests reach it only through the buffering nginx proxy.
  Exposing gunicorn's port lets one participant freeze the event with slow uploads.
- **No security property depends on a per-address limit.** A classroom shares one NAT address, so
  a rival can trip any per-address limit for everybody behind it.
  - Per-address limits are flood guards that count only provably bad requests, and a valid token
    is never limited.
  - They are listed in `admin.LOCKOUTS`, shown on the Events page, and the organiser can clear
    them there.
  - There is no team-password lockout. New team passwords need 8 characters and are checked
    against `ctf.COMMON_PASSWORDS`. The nginx join rate and `security._hashing` bound guessing.
  - The admin login lockout has a bypass no participant can block (`flask ... login-link`).
  - The public scoreboard is cached (`api.public_board`), not limited.
  - nginx has no per-address connection cap. It relies on short timeouts and small API bodies, and
    queues enrolments and joins (`/api/v1/enroll`, `/api/v1/ctf/join`) per address without ever
    refusing heartbeats or solves.
    `tools/slowloris_check.py` attacks from the same address it measures from.
- **Admin sessions are also server side** (`admin_sessions`). Logout ends the row, and `is_admin`
  checks it.
- **Strict CSP**: `default-src 'self'`. No inline `<script>`, no inline `style=""` and no external
  CDNs. Put CSS in `static/style.css` and JS in `static/*.js`.
- **Server time decides.** Ordering and tie-breaks use `received_at`. The device's `solved_at` is
  informational, because participants control their clocks.

## Trust model in one paragraph

CybICS flags are identical in every installation and printed in the training READMEs, and
participants have root on virtual instances. The server cannot prove a solve, so do not add features
that pretend it can. Anti-cheat is audit plus moderation:

- every submission goes to the `submissions` table;
- wrong flags are suspicious, because an unmodified landing page never sends them;
- the organiser can void solves, take devices out of events, retire devices and disqualify teams;
  every organiser action is logged.

Per-instance flags would be a CybICS-wide change and are discussed in `docs/ARCHITECTURE.md`.

## Coupling with CybICS

- The catalog is CybICS' `software/landing/ctf_config.json`, imported as-is. `ctf.parse_ctf_config`
  reads `categories.*.challenges[]` with `id`, `title`, `points`, `flag` and `type`. If CybICS
  changes that schema, update the parser and the `CATALOG` fixture in `tests/conftest.py`.
- Physical devices identify themselves by the STM32 UID, as 6 to 32 lower-case hex characters. It
  is the same value CybICS shows in the `cybics-<uid>` SSID.
- The client ships in CybICS from the release that replaces v1.2.4 on. Most file references into
  CybICS in `docs/` are pinned to v1.2.3. Re-check them when CybICS moves on.

## UI and branding

- The look follows the CybICS landing page (`software/landing/templates/index.html` in CybICS):
  - dark slate is the default when the OS states no preference; otherwise the theme follows the OS;
  - CybICS orange `#ff6b00` is the only accent;
  - a faint blueprint grid sits behind the content;
  - text is set in Inter, numbers in a mono face.
- The tokens are defined once on `:root` and overridden under `:root[data-theme="light"]`. Use
  `var(--...)` everywhere and never hard-code a colour in a rule.
- In light mode, orange text uses `--accent-text`, because `#ff6b00` fails contrast on white.
- `static/theme.js` runs synchronously in `<head>` and sets `data-theme` before first paint. The
  preference is `system`, `light` or `dark`, kept in `localStorage` under `cybics-mgmt-theme`.
- Brand assets are copies from CybICS. Replace them from there; do not edit them:
  - `static/img/cybics-logo.png` comes from `software/landing/pics/CybICS_logo.png`;
  - `static/img/favicon.ico` comes from `software/landing/pics/favicon.ico`;
  - `static/fonts/InterVariable.woff2` comes from `software/landing/static/fonts/` (SIL OFL; keep
    `Inter-LICENSE.txt` next to it).
- The scoreboard is projected in rooms. Keep it legible from a distance, and keep it refreshing
  through `/api/v1/events/<slug>/scoreboard` without a page reload. It has its own files:
  - `static/board.css`: the backdrop, glass cards, podium, rank-change and first-blood animations;
  - `static/scoreboard.js`: polling, FLIP row movement keyed by team name, count-up, the feed and
    the first-blood queue;
  - `static/board-bg.js`: the canvas network backdrop, capped at about 30 fps and paused in hidden
    tabs.

  Nothing animates on the first load, only changes after it. Every animation must stop under
  `prefers-reduced-motion`. Element styles are set only through the CSSOM (`el.style.x`,
  `el.animate()`), which the CSP allows; never through `style=""` or `setAttribute("style")`.
- To check animations, drive a real Chrome in real time, not `--virtual-time-budget`, which makes
  CSS animations unreliable. Load the scoreboard with a mocked `fetch` that returns two successive
  boards, and take screenshots through the DevTools protocol at chosen moments.
