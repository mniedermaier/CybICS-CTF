# Integrating with CybICS

This document lists the changes needed in the [CybICS](https://github.com/mniedermaier/CybICS)
repository so that installations can connect to this server. None of them changes how CybICS
behaves **until a user connects the installation in the landing page**: the feature is off by
default and optional.

The integration targets the CybICS release that replaces v1.2.4. That release ships the client
described here and speaks the API in [API.md](API.md); no earlier client is supported. File and line
references are against the CybICS tag `v1.2.3`, with function names given where they help to find
the place again once lines move.

## 1. Landing service (virtual and physical)

### Vendor the client

Copy `client/cybics_mgmt_client.py` to `software/landing/modules/cybics_mgmt.py`. It needs only the
standard library, so `requirements.txt` stays unchanged. Create one instance at import time, next to
the other managers (`app.py:44-47` in v1.2.3):

```python
from modules.cybics_mgmt import MgmtClient, MgmtClientError

mgmt = MgmtClient(
    state_path=os.path.join(DATA_DIR, "cybics_mgmt.json"),
    device_info=device_info,             # kind, device_uid, hostname, cybics_version, mode
    status=collect_mgmt_status,          # see below
    local_solves=read_progress_strict,   # must raise on a read error, see below
    flag_for=lambda cid: (ctf_manager.get_challenge(cid)[0] or {}).get("flag"),
    handlers=JOB_HANDLERS,               # see "Job handlers"
)
mgmt.start()   # sleeps until connected; no network traffic before that
```

`device_info()` returns the identity sent at enrolment:

- `kind`: `"physical"` on the Pi, `"virtual"` otherwise. An env var set in each compose file is the
  simplest switch (`CYBICS_PLATFORM=physical` in `software/docker-compose.yaml` and the rpi-image
  compose).
- `device_uid`: the STM32 UID on the Pi (see section 2). A physical device without one cannot enrol.
- `cybics_version`, `mode` and `hostname`.

`local_solves` must **raise** when the progress cannot be read. It must not return an empty list.
When the device joins a team, the client stores the current local solves as a baseline that is never
reported. If the callback returns an empty list because of a read error, every old solve on a reused
board is reported as new. Raising makes the join fail with `progress_unreadable`, and the user tries
again.

In v1.2.3, `CTFManager.load_progress` catches `JSONDecodeError` and returns empty progress, so
landing needs a strict variant for this callback:

```python
def read_progress_strict():
    if not os.path.exists(PROGRESS_FILE):
        return []                       # really no progress yet
    with open(PROGRESS_FILE, encoding="utf-8") as f:
        return json.load(f)["solved_challenges"]   # raises on a half-written file
```

### Report solves

Add one line after each successful local solve. That is `submit_flag()` (`app.py:421`; the branch
`if result['success']` is at line 433) and `verify_defense()` (`app.py:391`; the branch
`if submit_result['success']` is at line 407):

```python
mgmt.report_solve(challenge_id, submitted_flag)        # or result['flag'] in verify_defense
```

`report_solve` only appends to a file and wakes a thread, and only while the device is in an event
(or was taken out of one by the organiser). It never raises, even when the file cannot be written (a
full SD card), and never blocks, so it cannot fail or slow down the local submission. The background
thread also survives any error and backs off.

`POST /ctf/reset` (`app.py:456`) should leave the connection alone. A reset clears local progress
only; solves already reported stay on the scoreboard.

### Settings UI: Settings → CybICS-mgmt

The landing page already has a settings area (`/api/settings/*`). One new section covers the
connection, the CTF and management. Show `MgmtClientError.message` as-is everywhere; the server
writes it for end users.

- **Not connected** (default): an explanation that this is optional, and the fields *Server
  address*, *Code* (an enrolment code from the organiser, or an event's join code) and an optional
  *Label*.
  - **Test connection** calls `mgmt.test_connection(url)`.
  - **Connect** calls `mgmt.enroll(url, code, label)`.
- **Connected**:
  - the server, the device's label and group (`device`), the last contact and the last error;
  - **Event**: while in no event, the fields *Join code*, *Team name* and *Team password* and a
    **Join** button that calls `mgmt.join_event(join_code, team, password)`. Teammates enter the
    same team name and password. In an event: the event and team, the event state (show "waiting for
    start" in `draft`), score and rank (`ctf.standing`), pending reports (`ctf.pending`),
    announcements, and a **Leave event** button that calls `mgmt.leave_event()`. The organiser can
    also put the device into a team; the snapshot then shows it without the user doing anything.
    `ctf.removed` means the organiser took the device out: solves stay queued until it is back.
  - **Allowed actions**: one switch per action in `available` (the actions landing registered a
    handler for), all off after connecting; `mgmt.set_allowed([...])`. Switching everything off is
    the kill switch.
  - The signing key's fingerprint (`key_fingerprint`). The organiser's device page shows the same
    value, so a trainer can compare them.
  - The job queue and history (`queue`, `history`). `last_error` with the code `bad_signature`
    means somebody sent a forged job.
  - **Disconnect** calls `mgmt.leave()`. The device is retired on the server and leaves its event;
    connecting again enrols a new device.
  - `revoked` means the organiser retired the device: show it, and offer to connect again.
- Suggested routes:
  - `GET /api/settings/mgmt` returns `mgmt.snapshot()`, which never contains the token, the key or
    the baseline;
  - `POST /api/settings/mgmt/test`, `/connect`, `/join`, `/leave-event`, `/allowed` and
    `/disconnect`.

Optional: a small badge in the dashboard header ("CybICS-mgmt: rank 3/14"), a toast for new
announcements, and the banner for `identify` and `message` jobs. `index.html` already polls
`/ctf/progress`, so it can poll the snapshot too.

### Job handlers

The client **executes nothing by itself**: landing registers one handler per action, and only for
the actions it wants to offer. A handler gets the job's parameters, already checked by the server,
and returns a short result text (`collect_logs` returns the log text or bytes).

```python
JOB_HANDLERS = {
    "identify": lambda p: ui.banner(f"This is {mgmt.snapshot()['device']['label']}",
                                    seconds=p["seconds"]),
    "message": lambda p: ui.banner(p["text"], seconds=300),
    "restart": lambda p: restart.restart_project() if p["service"] == "all"
                         else restart.restart_service(p["service"]),
    "reset_progress": lambda p: ctf_manager.reset_progress(),
    "collect_logs": lambda p: logs.bundle_text(),   # the text of /api/settings/logs/download
}
```

`restart` with `all` takes landing down too. The client records the job as running before it starts,
and reports it as done after landing comes back.

### Status payload

`collect_mgmt_status()` should stay small and cheap. It runs every 30 s, and the server keeps at
most 16 KB of it. Everything is optional:

```python
def collect_mgmt_status():
    # get_docker_containers() serves StatsCollector's cache (no Docker call);
    # each entry carries 'name' and 'status' (the container State).
    containers = stats_collector.get_docker_containers()
    return {
        "cybics_version": os.environ.get("CYBICS_VERSION"),
        "mode": os.environ.get("CYBICS_MODE"),
        "hostname": socket.gethostname(),
        "services": {c["name"]: c["status"] == "running" for c in containers},
        "host": {...},    # CPU %, memory, disk, uptime, CPU temperature
        "board": {...},   # on a board: revision, firmware version, STM32 link, uplink SSID and signal
    }
```

The client adds `local_solved` itself. The CPU temperature is in
`/sys/class/thermal/thermal_zone0/temp`. Do **not** include anything that reveals the participant's
network beyond what the organiser needs.

### Persist landing's data directory

None of the compose files mounts `/CybICS/data`, so `ctf_progress.json` and the new
`cybics_mgmt.json` (which holds the device token and the outbox) are lost when the container is
recreated. Add a named volume to `landing` in all three compose files:

- `.devcontainer/virtual/docker-compose.yml`
- `software/docker-compose.yaml`
- `software/rpi-image/stage-cybics/02-load-containers/files/docker-compose.yaml`

### Version string

CybICS keeps its version only in `stm32/src/version.h` and `hwio-virtual/hardwareAbstraction.py`.
Landing should report one, so pass it in as `CYBICS_VERSION` (the compose files already use that
variable for image tags) or bake it in at image build time.

### Blast radius

`landing` runs with host networking, `NET_ADMIN` and the Docker socket. The client adds:

- one outbound HTTP(S) connection to a URL the user typed in;
- one file in landing's data directory;
- the actions the user switched on, each with fixed parameters checked by the server and the
  handler, and only from jobs signed with the key pinned when connecting.

It opens no listening port, and runs nothing at all while no action is allowed.

## 2. Physical device: second Wi-Fi interface

The onboard `wlan0` stays as it is: an AP for the training network (`cybics-<uid>`, `10.0.0.1/24`),
or a station joining `cybics`. A USB Wi-Fi dongle (`wlan1`) connects the board to the event network
where this server runs.

### Device identity

`hwio-raspberry` already reads the STM32 UID (`hardwareIO.py:391-395`) and puts it in the SSID.
Landing needs it for `device_uid`. Options, simplest first:

- have hwio write it to a file on a shared volume, e.g. `/run/cybics/device_uid`, which landing
  reads; or
- have hwio expose it through the existing Modbus/IPC path.

### Things that break with a second Wi-Fi profile, and the fixes

1. **hwio's station profile pick** (`detect_station_connection()`, `hardwareIO.py:223`). This is the one that must be fixed.
   - Today hwio returns *any* Wi-Fi profile not named `cybics` as "the station connection", and
     brings it up on `wlan0` when the board is in STA mode.
   - An uplink profile for `wlan1` would be picked by mistake.
   - Fix: ignore profiles whose `connection.interface-name` is not `wlan0`, or name the uplink
     `cybics-ctf-uplink` and exclude the `cybics-ctf-` prefix.
   - `tests/test_hwio_wifi.py` covers this function, so add a case there.
2. **Interface naming.**
   - The onboard chip must stay `wlan0`; `wlan0` is hard-coded in hwio, both `.nmconnection` files,
     `NetworkManager.conf` and `installRPI.sh`.
   - Depending on probe order, a USB dongle can come up as `wlan0`.
   - Pin it with a systemd `.link` file matched on the onboard driver path (`brcmfmac`), or bind the
     uplink profile to the dongle's MAC (`match-device=mac:...`).
3. **NAT from the training AP into the event network.**
   - The AP profile uses `ipv4.method=shared`, so NetworkManager masquerades AP clients out through
     the default route.
   - Once `wlan1` provides that route, every participant on the board's AP can reach the event
     network and the other teams' boards.
   - Fix: set `ipv4.never-default=yes` on the uplink, so it only carries the server's subnet, and
     add a forward drop from `wlan0` to `wlan1`, for example in the `DOCKER-USER` chain or an
     nftables table.
4. **Services listening on the uplink.**
   - Docker-published ports and the host-networked `landing` (80) and `ids` (8443) listen on all
     interfaces. Every board would expose OpenPLC, Modbus, S7 and the rest to the whole event network.
   - Because the training content is about attacking exactly these services, this matters.
   - Fix: on `wlan1`, allow only established/related traffic and drop new inbound connections. Use
     the `DOCKER-USER` chain for published ports and the host `INPUT` chain for the host-networked
     services.
5. **Packet capture in the landing page.**
   - `network_capture.py` lists and sniffs every interface, so participants could capture
     central-server traffic on `wlan1`.
   - Exclude the uplink interface (by name or by an env var) from the capture list.
   - `_get_host_network_stats()` (`stats_collector.py:68`, interface filter at line 78) also counts
     `wlan1` in the bandwidth figures; exclude it there too.
6. **IDS.** No change is needed. Its BPF filter `net 172.18.0.0/24` already excludes uplink traffic.

### Uplink profile

Ship this in the image, but disabled. Keyfiles only allow comments on lines of their own, never after
a value. Example `cybics-ctf-uplink.nmconnection`:

```ini
[connection]
id=cybics-ctf-uplink
type=wifi
interface-name=wlan1
autoconnect=true

[wifi]
mode=infrastructure
# The event network; editable from the landing page.
ssid=cybics-ctf

[wifi-security]
key-mgmt=wpa-psk
psk=change-me

[ipv4]
method=auto
# Reach the CTF server's subnet only; never route AP clients out.
never-default=true
route-metric=600

[ipv6]
method=disabled
```

Editing the SSID and PSK from the landing page means calling nmcli. hwio already does that through
the host D-Bus socket. Landing does not today, so either:

- route the request through hwio, keeping nmcli access in one service; or
- mount the D-Bus socket into landing as well.

The first option is preferred, because landing already has a large blast radius.

### The default network `cybics-mgmt`

The CybICS-mgmt Raspberry Pi image (README, "Raspberry Pi Image") hosts a Wi-Fi network
`cybics-mgmt` (password `cybics-mgmt`, 2.4 GHz) with the server at `http://10.42.0.1`, and creates the
enrolment code `CYBICS-BOARDS`. Boards join it on their own:

- **Uplink default.** The uplink profile above ships with `ssid=cybics-mgmt`, `psk=cybics-mgmt` and
  `autoconnect=true` instead of a disabled placeholder. A board with a dongle connects whenever the
  network is in range; the landing page can still change the network.
- **Enrolling on its own.** When the uplink is connected to the network named `cybics-mgmt` and the
  board is not enrolled, landing calls `client.enroll("http://10.42.0.1", "CYBICS-BOARDS")` with
  the STM32 UID as the label suggestion. It does that only on this network, never on another one,
  and never again after the user disconnected on purpose (remember it next to the client state).
  Being on that network is the opt-in the invariant "no network call until the user enrols" asks
  for; a board without a dongle, or away from the network, never calls out.
- **Nothing else follows.** The board allows no action and joins no event by itself. The organiser
  puts it into a team from the fleet; the user switches actions on at the board.
- A board whose enrolment is refused (`code_disabled`, `invalid_code`) waits until the network or
  the board restarts before it tries again, so a disabled code does not cause a stream of attempts.

The network's defaults are public, like the boards' own access points. The organiser changes the
password in `cybics-mgmt.txt` on the Pi and on the boards' landing pages together.

### LCD (optional)

The 16x2 LCD shows the `wlan0` IP. Showing the central-server state needs all of the following:

- a new protobuf field or message (`software/stm32/proto/cybics.proto`);
- an I²C handler change in `main.c`;
- a new screen;
- a mirror of the change in `hwio-virtual`, where `test_display_parity.py` enforces parity;
- a check of the STM32 I²C buffer sizes.

This is worth doing later; it is not needed for a first version.

## 3. Running the event network

For events with physical boards, the organiser provides one Wi-Fi network that the dongles join, with
this server on it. Two simple layouts:

- **Venue network.**
  - The server runs on a machine on the venue LAN.
  - Participants enter `http://<server-ip>:8000` in the landing page.
  - Virtual instances on participants' laptops reach the server over the same network or over the
    internet.
- **Self-contained.**
  - The organiser laptop runs the server and a hotspot, e.g.
    `nmcli dev wifi hotspot ifname wlan0 ssid cybics-ctf password ...`.
  - Boards join `cybics-ctf`, and the server sits at the hotspot's gateway address (NetworkManager
    defaults to `10.42.0.1`).
  - Avoid `10.0.0.0/24` for the event network: every board already uses it for its training AP.

If the server is reachable from the internet, put it behind TLS (see the README).
