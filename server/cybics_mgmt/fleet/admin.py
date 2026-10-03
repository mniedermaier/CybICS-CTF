"""
The fleet pages of the organiser UI: the device list, a device's page,
groups, enrolment codes and the fleet log. Every change is audited with an
action starting with "fleet_".
"""
from flask import Response, abort, current_app, flash, redirect, render_template, request, url_for

from .. import device_input
from ..admin import bp
from ..db import get_db, now
from ..security import admin_required, audit, client_ip
from . import jobs
from . import logic as fleet
from .signing import get_signer


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
    for d in devices:
        d["allowed"] = jobs.allowed_actions(d)
    return render_template("admin/fleet.html", devices=devices, counts=counts, groups=fleet.list_groups(db),
                           group_id=group_id, kind=kind, show_all=show_all, actions=jobs.ACTIONS,
                           newest=".".join(map(str, newest)) if newest else None)


@bp.get("/fleet/devices/<device_id>")
@admin_required
def fleet_device(device_id):
    db = get_db()
    device = _device_or_404(device_id)
    status = device_input.parse_status(device["status_json"])
    online = (device["last_seen"] or 0) >= now() - current_app.config["ONLINE_WINDOW"]
    signer = get_signer(current_app)
    services = sorted(status["services"]) if isinstance(status.get("services"), dict) else []
    return render_template("admin/device.html", device=device, status=status, online=online,
                           status_pretty=device_input.pretty_status(status), groups=fleet.list_groups(db),
                           instances=fleet.device_instances(db, device_id), actions=jobs.ACTIONS,
                           allowed=jobs.allowed_actions(device), services=services,
                           blocked=jobs.device_problem(device, signer.fingerprint),
                           signer=signer, jobs=jobs.list_jobs(db, device_id))


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


def _creator():
    return f"web {client_ip()}"


@bp.post("/fleet/devices/<device_id>/jobs")
@admin_required
def fleet_job_create(device_id):
    db = get_db()
    device = _device_or_404(device_id)
    action = request.form.get("action", "")
    job = jobs.create_job(db, get_signer(current_app), device, action, request.form.to_dict(), _creator())
    audit("fleet_job_create", device=device_id, job=job["id"], job_action=action, params=job["params_json"])
    flash("Sent. The device picks it up at its next check-in.", "ok")
    return redirect(url_for("admin.fleet_device", device_id=device_id))


@bp.post("/fleet/jobs/bulk")
@admin_required
def fleet_jobs_bulk():
    """One action for several devices; devices that cannot take it are skipped and counted."""
    db = get_db()
    action = request.form.get("action", "")
    if action not in jobs.ACTIONS:
        flash("Choose an action.", "error")
        return redirect(url_for("admin.fleet_devices"))
    signer = get_signer(current_app)
    created, skipped = [], 0
    for device_id in request.form.getlist("device_id")[:500]:
        device = fleet.get_device(db, device_id)
        if device is None or jobs.why_not(device, action, signer.fingerprint):
            skipped += 1
            continue
        created.append(jobs.create_job(db, signer, device, action, request.form.to_dict(), _creator())["id"])
    audit("fleet_jobs_bulk", job_action=action, jobs=len(created), skipped=skipped)
    flash(f"Sent to {len(created)} device(s)." + (f" Skipped {skipped} that cannot take it." if skipped else ""),
          "ok" if created else "error")
    return redirect(url_for("admin.fleet_devices", **{k: v for k, v in request.args.items() if k in
                                                       ("group", "kind", "all")}))


@bp.post("/fleet/jobs/<job_id>/cancel")
@admin_required
def fleet_job_cancel(job_id):
    db = get_db()
    job = jobs.get_job(db, job_id)
    if job is None:
        abort(404)
    if jobs.cancel(db, job_id):
        audit("fleet_job_cancel", device=job["device_id"], job=job_id, job_action=job["action"])
        flash("Cancelled. A device that already received it may still run it.", "ok")
    else:
        flash("This job has already finished.", "error")
    return redirect(url_for("admin.fleet_device", device_id=job["device_id"]))


@bp.get("/fleet/jobs/<job_id>/logs")
@admin_required
def fleet_job_logs_download(job_id):
    db = get_db()
    logs = jobs.get_logs(db, job_id)
    if logs is None:
        abort(404)
    device = fleet.get_device(db, logs["device_id"])
    name = "".join(c if c.isalnum() or c in "-_" else "-" for c in (device["label"] or device["id"][:8]))
    return Response(logs["content"], mimetype="application/gzip",
                    headers={"Content-Disposition": f'attachment; filename="{name}-logs-{job_id[:8]}.txt.gz"'})


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
