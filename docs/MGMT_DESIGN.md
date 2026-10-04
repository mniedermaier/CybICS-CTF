# CybICS-mgmt design

CybICS-CTF became **CybICS-mgmt**: the optional central server for CybICS keeps running CTF events,
and it also manages the CybICS installations themselves, virtual and physical. This document records
the analysis behind that step, the decisions taken and the plan. [ARCHITECTURE.md](ARCHITECTURE.md)
stays the reference for the CTF part and the device identity; this document adds the fleet part.

The findings about CybICS are from October 2026, from the state of CybICS that becomes the release
replacing v1.2.4. That release ships `MgmtClient` instead of v1.2.4's CTF-only client.

## Decisions

| Question | Decision |
|---|---|
| What is managed? | Virtual **and** physical installations. Both can be observed; both can be controlled once the person in charge of the device allows it on the device. |
| Scope of the first round | Phase 0 (restructure and rename), phase 1 (read-only fleet), phase 2 (commands). Updates and provisioning of images are phase 3. |
| Compatibility | None with earlier clients. CybICS-mgmt ships together with the CybICS release that replaces v1.2.4, so no deployed client has to be supported: no compatibility layer for the rename, no second identity. |
| Identity | The **device** is the only identity. It enrols once and its token authenticates every call. Taking part in an event is a membership of the device in a team (an *instance*), not a second enrolment. |
| API | `/api/v1` is a fresh contract ([API.md](API.md)), valid from that CybICS release on: one enrolment, one heartbeat, `/ctf/join` for teams. From then on it only grows; anything else needs `/api/v2`. |
| Repository | Renamed to `mniedermaier/CybICS-mgmt` once the restructure is merged. |

## What existed before

### On the server

- CybICS-CTF knew instances only as members of a team in an event, each with its own token:
  `instances.team_id` was `NOT NULL` with `ON DELETE CASCADE`, and so was `teams.event_id`.
  - A board without an event could not be represented.
  - Deleting an event or a team deleted its instances, and with them the board's history.
  - A physical board had no identity across events, and the organiser saw instances only per
    event.
- Generic and reusable as they were: admin login, server-side sessions, CSRF, `audit()`, the rate
  limiter, hashed bearer tokens, the heartbeat and its size-capped status payload.

### On the installations

- The CTF client already sent kind, hostname, version, mode and STM32 UID at enrolment, and service
  health and local solves every 30 s. That is most of what a fleet overview needs.
- It executed nothing: it "opens no listening port and runs no commands". Control needs a client
  that verifies jobs, which is why the client changed together with the server.
- A physical board is **outbound only** on its event uplink: `cybics-ctf-uplink.nft` drops every new
  inbound connection on `ctfwlan0`. Virtual instances sit behind laptop NAT. Management must be pull
  based: the device asks, the server answers.
- landing already has what control needs:
  - `utils/restart.py` restarts the CybICS compose project, landing last;
  - `/api/settings/logs/download` collects container logs and image tags;
  - psutil statistics (CPU, memory, disk, network) and container state through the Docker socket;
  - the STM32 UID and board revision on the shared `cybics_state` volume;
  - the uplink status in `/var/lib/cybics-uplink/status.json`.
- Missing on the instance: CPU temperature and throttling, an explicit STM32 link state, a scenario
  reset (only `/ctf/reset`, which clears progress), and any update path for the Pi other than
  reflashing the SD card.
- Resources: a Pi Zero 2 W has 512 MB of RAM and the image's container limits already add up to
  about 672 MB. Management lives inside landing, never in an extra container.

### Security of the instances

- landing has **no authentication**. Its webshell (`/api/webshell/execute`) runs any command, in a
  container with host networking, `NET_ADMIN` and the Docker socket. Anybody on the training network
  is root on every board and every laptop running CybICS. That is part of the training design, and
  it is outside this repository.
- The Pi image ships SSH with `pi`/`raspberry` and sudo, and one AP PSK on every board.

Consequences for management:

1. **Devices are hostile.** Participants can change what their device reports and what its
   management state says. Telemetry is display data and never proof, exactly like solves.
2. **The server must not become a master key.** A stolen admin session or a man in the middle on a
   classroom network must not turn into root on every device. Hence: allow-listed actions only,
   signed jobs, opt-in on the device, a kill switch on the device, an audit log on both sides.

## Target architecture

```
 CybICS installation                         CybICS-mgmt
┌──────────────────┐   /api/v1/enroll        ┌───────────────────────────────────────────────────┐
│ landing          │   /api/v1/heartbeat     │ devices ─┬─ group, enrolment code                 │
│  MgmtClient ─────┼───────────────────────► │          ├─ jobs (signed, sequenced), log bundles │
│  job handlers    │   /api/v1/ctf/join      │          └─ instances ── teams ── events          │
└──────────────────┘   /api/v1/solves        │               (one live)    │       └─ challenges │
                                             │                             └─ solves             │
                                             └───────────────────────────────────────────────────┘
```

One enrolment makes the installation a device. Its token authenticates the heartbeat, which carries
the status, the management settings and job results, and answers with jobs and the device's CTF
state. Joining a team, reporting solves and reading the catalog use the same token.

### Devices

A **device** is one CybICS installation: a virtual stack on one laptop, or one board. It is the only
identity on the server.

- Columns: internal id (uuid), token hash, label (the sticker on the board), group, kind, STM32
  UID, hostname, versions, the last status, the actions the device allows, enrolment time, last seen,
  `retired`.
- A device is never deleted, only retired, so its history and its jobs stay on record.
- The STM32 UID is shown and used to *suggest* that two devices are the same board. It never
  authenticates and is never acted on automatically (it is broadcast in the SSID).
- CTF participation is an `instances` row: the device's membership in a team (`instances.device_id`
  is `NOT NULL`). A device has at most one live instance; joining another team ends the previous
  one. Deleting a team or an event removes the participation, not the device.
- The device joins a team with the team's name and password (`POST /api/v1/ctf/join`), or the
  organiser puts it into a team from its fleet page without the password
  (`instances.joined_by = 'organiser'`). The client learns that from the `ctf` part of its next
  heartbeat answer. The organiser can also take the device out of its event there.
- Retiring a device, by the organiser or because the user disconnected it, ends its instance.
  Bringing a retired device back does not rejoin the event.

### Enrolment

- **Enrolment codes**: the organiser creates codes in the fleet UI, each with a default group, and
  can disable them. The join code of an event that is not finished also works as an enrolment code
  (without a group), so participants need only the one code they were given: they connect with it,
  then join a team with it.
- **The default network**: the Raspberry Pi image hosts `cybics-mgmt` and creates the enrolment
  code `CYBICS-BOARDS` (`MGMT_DEFAULT_ENROL_CODE`). CybICS boards whose USB dongle is on that network
  enrol with it on their own (CYBICS_INTEGRATION.md, "The default network"). The organiser disables
  the code to stop it; a restart never enables it again.
- **Provisioning file** for boards: a `cybics-mgmt.json` on the SD card's boot partition with the
  server URL, an enrolment code, a label and the allowed actions. A freshly flashed board enrols at
  first boot. Writing that file is the explicit opt-in the invariant "no network call until the user
  enrols" requires.
- The enrolment answer contains the device id, the bearer token (shown once, stored hashed) and the
  server's **job-signing public key**. The device pins that key. The fleet UI and the landing page
  both show its fingerprint, so a trainer can compare them; with HTTPS and the client's CA file
  option, the pinning is protected end to end.

### Telemetry

The heartbeat carries a status object, capped at 16 KB and a nesting depth of 8:

- host: CPU, memory, disk, uptime, CPU temperature, throttling;
- services: state, health and memory per container;
- board: revision, firmware version, STM32 UID, STM32 link state, uplink interface, SSID, address
  and signal;
- client: version, allowed actions, results of finished jobs.

The server keeps the last status per device, plus a few typed columns for the list view. Values are
clamped (`device_input.py`) and rendered through the same filters as the rest of the UI, so no
device input can cause a 500.

### Jobs

A job is one allow-listed action for one device:

| Action | Effect on the device | Parameters |
|---|---|---|
| `identify` | Shows a banner "this is &lt;label&gt;" on landing for a while. | seconds |
| `message` | Shows an organiser message on landing. | text |
| `restart` | Restarts one CybICS service or the whole compose project (`utils/restart.py`). | service or `all` |
| `reset_progress` | Clears the local CTF progress (`/ctf/reset`). | none |
| `collect_logs` | Uploads a log bundle (container logs, image tags), at most 256 KB compressed. | none |

Rules:

- There is no generic command, no shell and no file write. A new action needs a new client release.
- **Signed.** The server signs each job with its RSA-3072 key: PKCS#1 v1.5 over SHA-256 of the
  canonical JSON of `{device, seq, id, action, params}`. The client verifies with the pinned key in
  plain standard-library Python (`pow`, then a constant-time comparison with the expected encoding;
  it never parses the padding). The server signs with `cryptography`; the key lives in
  `/data/fleet_signing_key.pem` and is created on first start.
- **Sequenced.** `seq` increases per device. The client runs a job only if its `seq` is higher than
  the last one it accepted. That stops replays without trusting a clock (a Pi Zero has no RTC).
- **Allowed on the device.** The device owner enables management on the landing page, action by
  action. Everything is off by default; the provisioning file can preset it for boards. The device
  reports its allowed actions, the fleet UI offers only those, and the client refuses anything else
  as `refused` even when it is correctly signed. Switching management off is the kill switch.
- **Bounded.** A job that was not delivered within 24 hours expires on the server. The client runs
  jobs one at a time on its own thread; heartbeats keep going meanwhile.
- **Reported.** The result (`done`, `failed`, `refused`, with a short detail) goes back with the
  next heartbeat. A `restart` that takes landing down is persisted as started before it runs and
  reported as done after the restart.
- **Audited.** Creating, cancelling and finishing a job is in `admin_log`. The device keeps its own
  log of executed jobs, visible on the landing page.
- Nothing a job carries is valid beyond the device: no tokens, no shared passwords, no event-wide
  secrets. Putting a device into a team therefore is not a job: the organiser changes the membership
  on the server, and the device follows its heartbeat answer.

### Client

- `client/cybics_mgmt_client.py` stays one file, standard library only, Python 3.9 or later. It
  holds one class, `MgmtClient`: `enroll(url, code, label)`, `join_event(join_code, team, password)`,
  `leave_event()`, `leave()`, `set_allowed(actions)`, `report_solve(cid, flag)`, `snapshot()`,
  `test_connection(url)`, `start()` and `stop()`.
- It transports and verifies. It never executes anything itself: landing registers a handler per
  action, and the client calls only those, catching every error.
- The rules of the CTF sync are those of [ARCHITECTURE.md](ARCHITECTURE.md#sync-protocol): no
  network call before enrolment, nothing ever blocks or crashes landing, solves are queued through
  outages and while the device is out of its event, and answers for a token or an instance that is
  no longer current are discarded.
- CybICS vendors the file as `software/landing/modules/cybics_mgmt.py`.

### Admin UI

- Top-level navigation: **Fleet**, **Events**.
- Fleet list: label, kind, version (marked when older than the newest version in the fleet), online
  state, health, group, CTF team, allowed actions. Filters by group, kind and state.
- Device page: the last status, the job history, the actions it allows, its CTF participations
  with a form to put it into a team or take it out of its event, retire.
- Bulk actions on a selection or a group, for example "restart landing on every board of room 2".
- Enrolment codes, groups, the signing key's fingerprint.

## Phase 0: restructure and rename

Status: implemented.

The Python package became `cybics_mgmt` with `ctf/` and `fleet/` subpackages, the settings `MGMT_*`,
the database `cybics-mgmt.sqlite`, the Compose project `cybics-mgmt` with the service `server` and
the volume `data`, and the client `client/cybics_mgmt_client.py`. `/api/v1/info` answers
`"service": "cybics-mgmt"`. Because CybICS-mgmt ships with the CybICS release that replaces v1.2.4,
nothing of the old names is kept: existing CybICS-CTF databases are not migrated.

## Phase 1: read-only fleet

Status: implemented.

- Schema: `devices`, `device_groups`, `enrol_codes`; every instance belongs to a device.
- `POST /api/v1/enroll` creates the device; `POST /api/v1/heartbeat` stores its status.
- Fleet UI: list, device page, groups, codes, retire, putting a device into a team.

## Phase 2: commands

Status: implemented on the server and in the client; the landing side is specified in
[CYBICS_INTEGRATION.md](CYBICS_INTEGRATION.md#1-landing-service-virtual-and-physical) and still to
be done in CybICS. There is no `ctf_assign` action: with the device as the only identity, the
organiser puts a device into a team on the server, and the heartbeat answer carries it to the device.
No token or password ever travels in a job.

- Schema: `jobs` and `job_logs`.
- Signing key, job creation (single and bulk), delivery in the heartbeat answer, results,
  `collect_logs` upload with its own nginx location and size limit, expiry.
- `MgmtClient` with signature check, sequence, local policy and handler dispatch.
- CybICS: vendor the client, management settings on the landing page (enrol, actions on or off,
  executed jobs, key fingerprint), the handlers, the extended telemetry, the provisioning file.

## Phase 3, later

- Updates: the server as an offline image cache for a classroom without internet. Virtual devices
  pull a pinned version; boards load image tarballs from the server after a free-disk check.
- Scenario reset: restore the OpenPLC program, the FUXA project and changed credentials. This needs
  work in CybICS first.
- Uplink and Wi-Fi settings, an STM32 LED for `identify`.

## Invariants added by the fleet

- **Management is opt-in on the device, per action, off by default.** Without it, a device is only
  observed.
- **Jobs are allow-listed, signed, sequenced actions.** Never a shell, a file write or a generic
  command.
- **Device input is display data.** It is clamped, never trusted, and never decides anything for
  another device.
- **The device is the only identity.** Every instance belongs to a device; a device has at most one
  live instance, and retiring it ends that instance.
- **Devices are retired, never deleted**, and deleting an event or a team leaves the device.
- **A board UID never acts across teams.** A board joining a team in which its UID is live replaces
  that instance, only within the team.
- **Every job is audited** on the server and on the device.
- **CybICS still works without the server**, and a device with management switched on behaves
  exactly like one without as long as no job arrives.
- **A board enrols on its own only on the default network `cybics-mgmt`**, with the default code,
  and never again after the user disconnected it. Enrolling allows no action and joins no event.
