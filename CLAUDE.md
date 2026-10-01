# CLAUDE.md

Guidance for Claude Code and other AI assistants working in this repository.

CybICS-CTF is the **optional** central CTF server for [CybICS](https://github.com/mniedermaier/CybICS),
the open-source ICS security training platform. Virtual CybICS instances (Docker on a laptop) and
physical ones (a Raspberry Pi Zero 2 W board with a USB Wi-Fi dongle as uplink) enrol from their
landing page. Once enrolled, they report their team, status and solves, and the organiser runs a
shared scoreboard. Read `docs/ARCHITECTURE.md` before changing behaviour; it records the
investigation of CybICS that the design is based on.

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

- `server/cybics_ctf/`: the Flask app.
  - `__init__.py`: app factory and configuration (`CTF_*` environment variables).
  - `ctf.py`: all domain logic (events, catalog, teams, instances, solves, scoring). It has no
    request handling, and every function takes the DB connection.
  - `api.py`: the instance API under `/api/v1`.
  - `admin.py`: the organiser UI under `/admin`.
  - `public.py`: the start page, the scoreboard, `/healthz` and `/favicon.ico`.
  - `security.py`: tokens, hashing, the rate limiter, admin session and CSRF.
  - `db.py`: SQLite and migrations.
  - `views.py`: template filters, error pages and security headers.
  - `cli.py`: `flask --app cybics_ctf ...` commands.
- `server/tests/`: pytest. `test_client.py` runs the reference client against a live server.
- `client/cybics_ctf_client.py`: the reference client that CybICS' landing service vendors.
- `docs/`: `ARCHITECTURE.md` (design and trust model), `API.md` (the contract) and
  `CYBICS_INTEGRATION.md` (what has to change on the CybICS side).
- `docker-compose.yml`, `server/Dockerfile` and `proxy/nginx.conf`: the deployment. nginx (the only
  published port) runs in front of gunicorn, with the `/data` volume.
- `tools/slowloris_check.py`: proves that slow clients cannot starve gunicorn. CI runs it.
- `ruff.toml`: lint configuration, with `target-version = py39` for the client.

## Running and testing

```bash
cd server && pip install -r requirements-dev.txt && ruff check .. && pytest   # needs Python 3.12
CTF_ADMIN_PASSWORD=... docker compose up -d --build           # http://localhost:8000
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
- **The API is a contract with deployed CybICS releases.** Changes under `/api/v1` may only *add*
  fields or endpoints. Renaming, removing or changing the meaning of anything needs `/api/v2`, served
  alongside v1. Update `docs/API.md` in the same change.
- **Every `/solves` answer except 5xx, 401, 403 and 429 is final for that solve.** The client takes
  the item out of the outbox on any `result` value, including ones it does not know, and on any
  other 4xx.
  - Unknown values are treated like `invalid_flag`. So a new `result` value in v1 must be safe to
    treat that way.
  - The one exception is `unknown_challenge`: the client holds the solve and retries it once the
    heartbeat's `catalog_version` changes.
- **Moderation never deletes evidence.** Removing a solve sets `solves.voided`; the solve stays in
  the team's `solved` list, so clients do not report it again. Deleting a team keeps its
  `submissions` rows (`team_id` becomes NULL, and `team_name` is a snapshot). Keep it that way.
- **The client never takes landing down.** `report_solve` never raises, `_request` turns every
  transport problem into `CTFClientError`, and the sender thread catches everything and backs off.
- **A board UID never acts across teams.** It is broadcast in the SSID. Re-enrolment revokes only
  the same team's instances; a UID seen in two teams is logged and flagged, never acted on.
- **Event state changes follow `ctf.TRANSITIONS`.** Nothing returns to `draft`.
- **Client answers are checked against the enrolment.** Every request remembers the token it was
  sent with, and an answer for a token that is no longer current is discarded. Keep that check
  around any new state the client updates from a response.
- **Instance input never causes a 500.** String fields go through `ctf._text()`; numbers from
  instances are clamped or dropped (`_client_time`, `announcements_after`). The template filters
  `time` and `ago` return `-` for anything they cannot render.
- **The client stays a single file using only the standard library, on Python 3.9 or later.** It is
  copied into CybICS (`software/landing/modules/central_ctf.py`), which ships with no extra
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
- **Secrets are never empty.** `_persistent_secret` replaces an empty or short file, and
  `check_admin_password` refuses an empty password on either side.
- **Slow hashing stays outside the write lock, and never queues for long.** Team passwords are
  hashed and checked before `transaction()`, through `security.hash_password`/`verify_password`.
  Those wait at most `HASH_WAIT` for one of two slots, then raise `HashingBusy` (503). Cheap refusals
  (banned team, instance cap) come before any hashing.
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
    against `ctf.COMMON_PASSWORDS`. The nginx enrolment rate and `security._hashing` bound guessing.
  - The admin login lockout has a bypass no participant can block (`flask ... login-link`).
  - The public scoreboard is cached (`api.public_board`), not limited.
  - nginx has no per-address connection cap. It relies on short timeouts and small API bodies, and
    queues enrolments per address without ever refusing heartbeats or solves.
    `tools/slowloris_check.py` attacks from the same address it measures from.
- **Admin sessions are also server side** (`admin_sessions`). Logout ends the row, and `is_admin`
  checks it.
- **Strict CSP**: `default-src 'self'`. No inline `<script>`, no inline `style=""` and no external
  CDNs. Put CSS in `static/style.css` and JS in `static/*.js`.
- **Server time decides.** Ordering and tie-breaks use `received_at`. The instance's `solved_at` is
  informational, because participants control their clocks.

## Trust model in one paragraph

CybICS flags are identical in every installation and printed in the training READMEs, and
participants have root on virtual instances. The server cannot prove a solve, so do not add features
that pretend it can. Anti-cheat is audit plus moderation:

- every submission goes to the `submissions` table;
- wrong flags are suspicious, because an unmodified landing page never sends them;
- the organiser can void solves, revoke instances and disqualify teams; every organiser action is logged.

Per-instance flags would be a CybICS-wide change and are discussed in `docs/ARCHITECTURE.md`.

## Coupling with CybICS

- The catalog is CybICS' `software/landing/ctf_config.json`, imported as-is. `ctf.parse_ctf_config`
  reads `categories.*.challenges[]` with `id`, `title`, `points`, `flag` and `type`. If CybICS
  changes that schema, update the parser and the `CATALOG` fixture in `tests/conftest.py`.
- Physical instances identify themselves by the STM32 UID, as 6 to 32 lower-case hex characters. It
  is the same value CybICS shows in the `cybics-<uid>` SSID.
- File references into CybICS in `docs/` are pinned to v1.2.3. Re-check them when CybICS moves on.

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
  preference is `system`, `light` or `dark`, kept in `localStorage` under `cybics-ctf-theme`.
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
