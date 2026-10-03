"""
The fleet pages of the organiser UI: the device list, a device's page,
groups, enrolment codes and the fleet log. Every change is audited with an
action starting with "fleet_".
"""
from flask import abort, current_app, flash, redirect, render_template, request, url_for

from .. import device_input
from ..admin import bp
from ..db import get_db, now
from ..security import admin_required, audit
from . import logic as fleet


def _device_or_404(device_id):
    device = fleet.get_device(get_db(), device_id)
    if device is None:
        abort(404)
    return device


def _int_or_none(value):
    try:
        return int(str(value)[:9])
    except (TypeError, ValueError):
        return None


@bp.get("/fleet")
@admin_required
def fleet_devices():
    db = get_db()
    group_id = _int_or_none(request.args.get("group"))
    kind = request.args.get("kind") if request.args.get("kind") in device_input.DEVICE_KINDS else None
    show_all = request.args.get("all") == "1"
    devices, newest = fleet.list_devices(db, now() - current_app.config["ONLINE_WINDOW"], group_id=group_id,
                                         kind=kind, include_gone=show_all)
    counts = {state: sum(1 for d in devices if d["state"] == state) for state in ("online", "offline", "gone")}
    return render_template("admin/fleet.html", devices=devices, counts=counts, groups=fleet.list_groups(db),
                           group_id=group_id, kind=kind, show_all=show_all,
                           newest=".".join(map(str, newest)) if newest else None)


@bp.get("/fleet/devices/<device_id>")
@admin_required
def fleet_device(device_id):
    db = get_db()
    device = _device_or_404(device_id)
    status = device_input.parse_status(device["status_json"])
    online = (device["last_seen"] or 0) >= now() - current_app.config["ONLINE_WINDOW"]
    return render_template("admin/device.html", device=device, status=status, online=online,
                           status_pretty=device_input.pretty_status(status), groups=fleet.list_groups(db),
                           instances=fleet.device_instances(db, device_id))


@bp.post("/fleet/devices/<device_id>")
@admin_required
def fleet_device_update(device_id):
    _device_or_404(device_id)
    fleet.update_device(get_db(), device_id, request.form.get("label", ""), request.form.get("group", ""),
                        request.form.get("notes", ""))
    audit("fleet_device_update", device=device_id, label=request.form.get("label", ""))
    flash("Device saved.", "ok")
    return redirect(url_for("admin.fleet_device", device_id=device_id))


@bp.post("/fleet/devices/<device_id>/<action>")
@admin_required
def fleet_device_action(device_id, action):
    if action not in ("retire", "restore"):
        abort(404)
    _device_or_404(device_id)
    fleet.set_retired(get_db(), device_id, action == "retire")
    audit(f"fleet_device_{action}", device=device_id)
    flash("Device retired: its token stops working and it leaves the list." if action == "retire"
          else "Device back in service.", "ok")
    return redirect(url_for("admin.fleet_device", device_id=device_id))


@bp.get("/fleet/setup")
@admin_required
def fleet_setup():
    db = get_db()
    return render_template("admin/fleet_setup.html", groups=fleet.list_groups(db), codes=fleet.list_codes(db))


@bp.post("/fleet/groups")
@admin_required
def fleet_group_create():
    group = fleet.create_group(get_db(), request.form.get("name", ""))
    audit("fleet_group_create", group=group["name"])
    flash(f"Group '{group['name']}' created.", "ok")
    return redirect(url_for("admin.fleet_setup"))


@bp.post("/fleet/groups/<int:group_id>/delete")
@admin_required
def fleet_group_delete(group_id):
    db = get_db()
    group = db.execute("SELECT name FROM device_groups WHERE id = ?", (group_id,)).fetchone()
    if group is None:
        abort(404)
    fleet.delete_group(db, group_id)
    audit("fleet_group_delete", group=group["name"])
    flash(f"Group '{group['name']}' deleted; its devices and codes stay, without a group.", "ok")
    return redirect(url_for("admin.fleet_setup"))


@bp.post("/fleet/codes")
@admin_required
def fleet_code_create():
    code = fleet.create_code(get_db(), request.form.get("label", ""), request.form.get("group", ""))
    audit("fleet_code_create", code_id=code["id"], label=code["label"])
    flash(f"Enrolment code {code['code']} created.", "ok")
    return redirect(url_for("admin.fleet_setup"))


@bp.post("/fleet/codes/<int:code_id>/<action>")
@admin_required
def fleet_code_action(code_id, action):
    if action not in ("enable", "disable"):
        abort(404)
    db = get_db()
    if not db.execute("SELECT 1 FROM enrol_codes WHERE id = ?", (code_id,)).fetchone():
        abort(404)
    fleet.set_code_enabled(db, code_id, action == "enable")
    audit(f"fleet_code_{action}", code_id=code_id)
    flash("Code enabled." if action == "enable" else "Code disabled; devices already enrolled stay.", "ok")
    return redirect(url_for("admin.fleet_setup"))


@bp.get("/fleet/log")
@admin_required
def fleet_log():
    entries = get_db().execute(r"""SELECT * FROM admin_log WHERE action LIKE 'fleet\_%' ESCAPE '\'
                                   ORDER BY created_at DESC LIMIT 1000""").fetchall()
    return render_template("admin/fleet_log.html", entries=entries)
