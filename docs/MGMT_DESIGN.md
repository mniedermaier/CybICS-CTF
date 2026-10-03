# CybICS-mgmt design

CybICS-CTF becomes **CybICS-mgmt**: the optional central server for CybICS keeps running CTF events,
and it also manages the CybICS installations themselves, virtual and physical. This document records
the analysis behind that step, the decisions taken and the plan. [ARCHITECTURE.md](ARCHITECTURE.md)
stays the reference for the CTF part; this document adds the fleet part.

The findings about CybICS are pinned to CybICS v1.2.4 (October 2026), the first release that ships
the client.

## Decisions

| Question | Decision |
|---|---|
| What is managed? | Virtual **and** physical installations. Both can be observed; both can be controlled once the person in charge of the device allows it on the device. |
| Scope of the first round | Phase 0 (restructure and rename), phase 1 (read-only fleet), phase 2 (commands). Updates and provisioning of images are phase 3. |
| API | No `/api/v2`. The fleet gets new endpoints under `/api/v1/fleet/`, which the v1 contract allows. The CTF endpoints do not change at all. |
| Repository | Renamed to `mniedermaier/CybICS-mgmt` once the restructure is merged. |

## What exists today

### On the server

- Instances exist only as members of a team in an event: `instances.team_id` is `NOT NULL` with
  `ON DELETE CASCADE`, and so is `teams.event_id`.
  - A board without an event cannot be represented.
  - Deleting an event or a team deletes its instances, and with them the board's history.
  - A physical board has no identity across events, and the organiser sees instances only per
    event.
- Generic and reusable as they are: admin login, server-side sessions, CSRF, `audit()`, the rate
  limiter, hashed bearer tokens, the heartbeat and its size-capped status payload.

### On the instances

- CybICS v1.2.4 ships the client (`software/landing/modules/central_ctf.py`,
  byte-identical to `client/cybics_ctf_client.py`). Each heartbeat already sends:
  - kind, hostname, version, mode and STM32 UID (at enrolment);
  - service health and local solves (every 30 s).

  A cross-event fleet overview therefore works **with releases already deployed**.
- The client ignores unknown fields in answers, so answers can grow. It executes nothing: it "opens
  no listening port and runs no commands". Control needs a new client release.
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
                     ┌──────────────────────────── CybICS-mgmt ────────────────────────────┐
 CybICS installation │  fleet                                     ctf                      │
┌──────────────────┐ │  devices ─ groups ─ enrol codes            events ─ challenges      │
│ landing          │ │     │                                         └─ teams ─ instances ─┼─ solves
│  CTFClient   ────┼─┼─────┼──── /api/v1/enroll, /heartbeat, /solves ───────────┘          │
│  FleetClient ────┼─┼── /api/v1/fleet/enroll, /fleet/heartbeat, /fleet/jobs/<id>          │
│  job handlers    │ │     └─ jobs (signed, sequenced) ─ job results ─ log bundles          │
└──────────────────┘ └──────────────────────────────────────────────────────────────────────┘
```

### Devices

A **device** is one CybICS installation: a virtual stack on one laptop, or one board. It is the
lasting identity in the fleet.

- Columns: internal id (uuid), token hash, label (the sticker on the board), group, kind, STM32
  UID, hostname, versions, the last status, the actions the device allows, enrolment time, last seen,
  `retired`.
- A device is never deleted, only retired, so its history and its jobs stay on record.
- The STM32 UID is shown and used to *suggest* that two devices are the same board. It never
  authenticates and is never acted on automatically (it is broadcast in the SSID).
- CTF participation stays the `instances` row it is today, linked to its device through a new
  nullable `instances.device_id`. Deleting a team or an event removes the participation, not the
  device.
- v1 enrolments of deployed clients get a device too. Such a device is marked `legacy`: it shows up
  in the fleet with its telemetry, and offers no actions.

### Enrolment into the fleet

- **Enrolment codes**: the organiser creates codes in the fleet UI, each with a default group, and
  can disable them. An event join code also works as an enrolment code, so participants type one
  code for both.
- **Provisioning file** for boards: a `cybics-mgmt.json` on the SD card's boot partition with the
  server URL, an enrolment code, a label and the allowed actions. A freshly flashed board enrols at
  first boot. Writing that file is the explicit opt-in the invariant "no network call until the user
  enrols" requires.
- The enrolment answer contains the device id, the bearer token (shown once, stored hashed) and the
  server's **job-signing public key**. The device pins that key. The fleet UI and the landing page
  both show its fingerprint, so a trainer can compare them; with HTTPS and the client's CA file
  option, the pinning is protected end to end.

### Telemetry

The fleet heartbeat carries a status object, capped like today (16 KB, depth 8):

- host: CPU, memory, disk, uptime, CPU temperature, throttling;
- services: state, health and memory per container;
- board: revision, firmware version, STM32 UID, STM32 link state, uplink interface, SSID, address
  and signal;
- client: version, allowed actions, results of finished jobs.

The server keeps the last status per device, plus a few typed columns for the list view. Values are
clamped and rendered through the same filters as today, so no device input can cause a 500.

### Jobs

A job is one allow-listed action for one device:

| Action | Effect on the device | Parameters |
|---|---|---|
| `identify` | Shows a banner "this is &lt;label&gt;" on landing for a while. | label, seconds |
| `message` | Shows an organiser message on landing. | text |
| `restart` | Restarts one CybICS service or the whole compose project (`utils/restart.py`). | service or `all` |
| `reset_progress` | Clears the local CTF progress (`/ctf/reset`). | none |
| `collect_logs` | Uploads a log bundle (container logs, image tags), at most 256 KB compressed. | none |
| `ctf_assign` | Joins or leaves a CTF event with a server-issued v1 instance token. | event, token or `leave` |

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
- Nothing a job carries is valid beyond the device: no shared passwords, no event-wide secrets.

### Client

- `client/cybics_mgmt_client.py` stays one file, standard library only, Python 3.9 or later. It
  holds `CTFClient` with its current behaviour and API, and the new `FleetClient`.
- `FleetClient` transports and verifies. It never executes anything itself: landing registers a
  handler per action, and the client calls only those, catching every error.
- The invariants of the CTF client apply unchanged: no network call before enrolment, nothing ever
  blocks or crashes landing, answers for a token that is no longer current are discarded.
- CybICS vendors the file as `software/landing/modules/cybics_mgmt.py`, replacing `central_ctf.py`.

### Admin UI

- Top-level navigation: **Fleet**, **Events**.
- Fleet list: label, kind, version (marked when older than the newest version in the fleet), online
  state, health, group, CTF assignment, allowed actions. Filters by group, kind and state.
- Device page: the last status, the job history, the actions it allows, retire.
- Bulk actions on a selection or a group, for example "restart landing on every board of room 2".
- Enrolment codes, groups, the signing key's fingerprint.

## Phase 0: restructure and rename

The rename must not break deployed CybICS releases or existing installations.

| Item | Today | After | Compatibility |
|---|---|---|---|
| Python package | `cybics_ctf` | `cybics_mgmt`, with `ctf/` and `fleet/` subpackages | A `cybics_ctf` shim keeps `flask --app cybics_ctf` working. |
| `/api/v1/info` | `"service": "cybics-ctf"` | unchanged, plus `"product": "cybics-mgmt"` and `"features"` | Deployed clients check `service`; it never changes in v1. |
| Environment | `CTF_*` | `MGMT_*` | `CTF_*` is still read when the `MGMT_*` name is unset, with a warning. |
| Database file | `cybics-ctf.sqlite` | `cybics-mgmt.sqlite` | Renamed once at start, with its `-wal` and `-shm`, under the migration lock. |
| Backups | `cybics-ctf-*.sqlite` | `cybics-mgmt-*.sqlite` | `--keep` prunes both prefixes. |
| Compose | project from the directory, service `ctf-server`, volume `ctf-data` | `name: cybics-mgmt`, service `server`, volume `data` | The volume name changes. The README gives the one-off command that copies the old volume. |
| Theme storage | `cybics-ctf-theme` | `cybics-mgmt-theme` | The old key is read when the new one is missing. |
| Client file | `client/cybics_ctf_client.py` | `client/cybics_mgmt_client.py` | Deployed CybICS keeps its own copy until it vendors the new file. |
| Display name | "CybICS CTF" | "CybICS-mgmt" | Configurable as before. |

Docs, CLAUDE.md, CI and the README badges move with it.

## Phase 1: read-only fleet

- Migration: `devices`, `device_groups`, `enrol_codes`, `instances.device_id`; a device for every
  existing instance (`legacy`).
- v1 enrolment creates or links the device; the v1 heartbeat updates its status.
- `/api/v1/fleet/enroll` and `/api/v1/fleet/heartbeat` for the new client.
- Fleet UI: list, device page, groups, codes, retire.
- No CybICS change is needed for the legacy view.

## Phase 2: commands

- Migration: `jobs` and `job_logs`.
- Signing key, job creation (single and bulk), delivery in the heartbeat answer, results,
  `collect_logs` upload with its own nginx location and size limit, expiry.
- `FleetClient` with signature check, sequence, local policy and handler dispatch.
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
- **Devices are retired, never deleted**, and deleting an event or a team leaves the device.
- **Every job is audited** on the server and on the device.
- **CybICS still works without the server**, and a device with management switched on behaves
  exactly like one without as long as no job arrives.
