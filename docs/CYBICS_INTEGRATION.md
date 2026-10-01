# Integrating with CybICS

This document lists the changes needed in the [CybICS](https://github.com/mniedermaier/CybICS)
repository so that instances can connect to this server. None of them changes how CybICS behaves
**until a user enables the central server in the landing page**: the feature is off by default and
optional.

File and line references are against the CybICS tag `v1.2.3`, with function names given where they
help to find the place again once lines move.

## 1. Landing service (virtual and physical)

### Vendor the client

Copy `client/cybics_ctf_client.py` to `software/landing/modules/central_ctf.py`. It needs only the
standard library, so `requirements.txt` stays unchanged. Create one instance at import time, next to
the other managers (`app.py:44-47` in v1.2.3):

```python
from modules.central_ctf import CTFClient, CTFClientError

central = CTFClient(
    state_path=os.path.join(DATA_DIR, "central_ctf.json"),
    local_solves=read_progress_strict,   # must raise on a read error, see below
    flag_for=lambda cid: (ctf_manager.get_challenge(cid)[0] or {}).get("flag"),
    status=collect_central_status,   # see below
)
central.start()   # sleeps until enrolled; no network traffic while disabled
```

`local_solves` must **raise** when the progress cannot be read. It must not return an empty list. At
enrolment, the client stores the current local solves as a baseline that is never reported. If the
callback returns an empty list because of a read error, every old solve on a reused board is
reported as new. Raising makes the enrolment fail with `progress_unreadable`, and the user tries
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
central.report_solve(challenge_id, submitted_flag)        # or result['flag'] in verify_defense
```

`report_solve` only appends to a file and wakes a thread. It never raises, even when the file cannot
be written (a full SD card), and never blocks, so it cannot fail or slow down the local submission.
The background thread also survives any error and backs off.

`POST /ctf/reset` (`app.py:456`) should leave the central enrolment alone. A reset clears local progress only;
solves already reported stay on the scoreboard.

### Settings UI: Settings → Central CTF server

The landing page already has a settings area (`/api/settings/*`). The new section needs:

- **Off** (default): an explanation that this is optional, and the fields *Server address*, *Join
  code*, *Team name* and *Team password*.
  - A **Test connection** button calls `central.test_connection(url)`.
  - A **Join** button calls `central.enroll(...)`.
  - Show `CTFClientError.message` as-is; the server writes it for end users.
- **On**:
  - the server and team name;
  - the event state (show "waiting for start" in `draft`);
  - score and rank (`standing`);
  - pending reports (`pending`), the last contact and the last error;
  - announcements;
  - a **Leave** button that calls `central.leave()`.
- Suggested routes:
  - `GET /api/settings/central` returns `central.snapshot()`, which never contains the token;
  - `POST /api/settings/central/test`;
  - `POST /api/settings/central/enroll`;
  - `POST /api/settings/central/leave`.
- The `instance` dict sent to `enroll`:
  - `kind`: `"physical"` on the Pi, `"virtual"` otherwise. An env var set in each compose file is
    the simplest switch (`CYBICS_PLATFORM=physical` in `software/docker-compose.yaml` and the
    rpi-image compose).
  - `device_uid`: the STM32 UID on the Pi (see section 2).
  - `cybics_version`, `mode` and `hostname`.

Optional: a small badge in the dashboard header ("Central CTF: rank 3/14") and a toast for new
announcements. `index.html` already polls `/ctf/progress`, so it can poll the snapshot too.

### Status payload

`collect_central_status()` should stay small and cheap. It runs every 30 s, and the server keeps at
most 16 KB of it.

```python
def collect_central_status():
    # get_docker_containers() serves StatsCollector's cache (no Docker call);
    # each entry carries 'name' and 'status' (the container State).
    containers = stats_collector.get_docker_containers()
    return {
        "cybics_version": os.environ.get("CYBICS_VERSION"),
        "mode": os.environ.get("CYBICS_MODE"),
        "services": {c["name"]: c["status"] == "running" for c in containers},
        "local_solved": ctf_manager.load_progress()["solved_challenges"],
    }
```

Do **not** include anything that reveals the participant's network beyond what the organiser needs.

### Persist landing's data directory

None of the compose files mounts `/CybICS/data`, so `ctf_progress.json` and the new `central_ctf.json`
(which holds the instance token) are lost when the container is recreated. Add a named volume to
`landing` in all three compose files:

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
- one file in landing's data directory.

It opens no listening port and runs no commands.

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
