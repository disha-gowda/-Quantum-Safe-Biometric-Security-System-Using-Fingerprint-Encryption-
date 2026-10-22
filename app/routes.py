"""Flask routes: group encrypt/decrypt, chat, edits, dashboard analysis."""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_file, session, url_for

from app.database import (
    add_session_decryptor,
    can_edit,
    chat_payload,
    delete_session,
    get_message_edits,
    get_participants,
    get_session,
    list_sessions,
    log_decrypt,
    remove_session_decryptor,
    save_group_session,
    update_message,
    verify_encryptor,
    verify_encryptor_fingerprint,
)
from app.services import (
    build_auth_analysis,
    content_from_encrypt_form,
    dashboard_biometric_panel,
    persist_download,
    probe_from_fingerprint,
    profile_from_form,
    reject_decryptor_face_live,
    resolve_prefixed_biometrics,
)
from app.benchmark_cache import get_cached, invalidate, run_and_cache
from app.session_metrics import session_security_metrics
from app.timefmt import format_ist, format_ist_list
from qsbas.biometric_profile import (
    BiometricProfile,
    identify_participant,
    verify_decrypt_authorization,
)
from qsbas.biometric_validation import BiometricValidationError
from qsbas.constants import EDIT_WINDOW_SECONDS, MAX_AUTHORIZED_USERS
from qsbas.group_cipher import GroupEncryptedMessage, group_decrypt_by_fingerprint, group_encrypt
from qsbas.cipher import QSBACCipher
from qsbas.payload import unpack_payload, replace_text, pack_payload, preview_text

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    _clear_all_chat_access()
    sessions = list_sessions()
    return render_template("index.html", sessions=sessions, max_users=MAX_AUTHORIZED_USERS)


@bp.route("/encrypt", methods=["GET", "POST"])
def encrypt_page():
    if request.method == "GET":
        return render_template("encrypt.html", max_users=MAX_AUTHORIZED_USERS)

    label = request.form.get("label", "secure-chat")
    encryptor_name = request.form.get("encryptor_name", "").strip()

    if not encryptor_name:
        flash("Encryptor name is required.")
        return redirect(url_for("main.encrypt_page"))

    enc_fp, enc_face = resolve_prefixed_biometrics(request, "encryptor_")
    if not enc_fp and not enc_face:
        flash("Encryptor biometrics required: fingerprint, face, or both (upload or live capture).")
        return redirect(url_for("main.encrypt_page"))

    try:
        blob, preview = content_from_encrypt_form(request)
        participants: list[BiometricProfile] = []
        participant_meta: list[dict] = []

        enc_profile, enc_meta = profile_from_form(
            encryptor_name,
            enc_fp,
            enc_face,
            is_encryptor=True,
        )
        participants.append(enc_profile)
        participant_meta.append(
            {"slot": 0, "name": encryptor_name, "is_encryptor": True, **enc_meta}
        )

        slots_raw = request.form.get("decryptor_slots", "").strip()
        slot_ids = [int(s) for s in slots_raw.split(",") if s.strip().isdigit()]
        for slot in slot_ids:
            name = request.form.get(f"user{slot}_name", "").strip()
            fp, face = resolve_prefixed_biometrics(request, f"user{slot}_")
            if not name or (not fp and not face):
                flash("Each decryptor needs a name and at least one biometric (fingerprint, face, or both).")
                return redirect(url_for("main.encrypt_page"))
            if face:
                reject_decryptor_face_live(request, f"user{slot}_")
            profile, meta = profile_from_form(
                name,
                fp,
                face,
            )
            participants.append(profile)
            participant_meta.append({"slot": len(participant_meta), "name": name, "is_encryptor": False, **meta})

        package = group_encrypt(blob, participants)
        session_id = save_group_session(
            label,
            encryptor_name,
            package.to_json(),
            enc_meta["fp_path"],
            participant_meta,
            original_plaintext=preview,
        )
        invalidate(session_id)
        session.pop(f"chat_unlock_{session_id}", None)
        session.pop(f"decrypted_{session_id}", None)
        flash(
            f"Encrypted for {len(participants)} authorized user(s). Session #{session_id}. "
            "Decrypt with the same enrolled factor(s): fingerprint, face, or both."
        )
        return redirect(url_for("main.index"))
    except BiometricValidationError as exc:
        flash(str(exc))
        return redirect(url_for("main.encrypt_page"))
    except Exception as exc:
        flash(f"Encryption failed: {exc}")
        return redirect(url_for("main.encrypt_page"))


def _session_authorized_map() -> dict[int, list[dict]]:
    """Session id -> participant summary for decrypt UI."""
    out: dict[int, list[dict]] = {}
    for s in list_sessions():
        sid = int(s["id"])
        parts = get_participants(sid)
        out[sid] = [
            {
                "name": p["name"],
                "is_encryptor": bool(p["is_encryptor"]),
            }
            for p in parts
        ]
    return out


@bp.route("/api/session/<int:session_id>/authorized")
def session_authorized(session_id: int):
    parts = get_participants(session_id)
    if not parts:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(
        {
            "session_id": session_id,
            "authorized": [
                {"name": p["name"], "is_encryptor": bool(p["is_encryptor"])}
                for p in parts
            ],
        }
    )


def _decrypt_context(sessions, auth_status=None, auth_analysis=None):
    return dict(
        sessions=sessions,
        authorized_map=_session_authorized_map(),
        max_users=MAX_AUTHORIZED_USERS,
        auth_status=auth_status,
        auth_analysis=auth_analysis,
    )


def _probe_auth_analysis(session_id: int, probe, paths: dict):
    participants = get_participants(session_id)
    if not participants:
        return None
    from qsbas.biometric_profile import face_match_score, fingerprint_match_score

    profiles = [(p, BiometricProfile.from_json(p["profile_json"])) for p in participants]
    best_row, best_profile = max(
        profiles,
        key=lambda item: fingerprint_match_score(item[1], probe) + face_match_score(item[1], probe),
    )
    return build_auth_analysis(
        best_profile,
        probe,
        paths.get("fp_path"),
        paths.get("face_path"),
        best_row["name"],
    )


@bp.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    sessions = list_sessions()
    if request.method == "GET":
        return render_template("decrypt.html", **_decrypt_context(sessions))

    session_id = request.form.get("session_id", type=int)
    fp_file, face_f = resolve_prefixed_biometrics(request, "")

    if not session_id:
        flash("Session is required.")
        return redirect(url_for("main.decrypt_page"))

    if not fp_file and not face_f:
        flash("Provide fingerprint, face, or both. Decryption denied.")
        return render_template(
            "decrypt.html",
            **_decrypt_context(
                sessions,
                auth_status={
                    "fingerprint": "Failed",
                    "face": "Failed",
                    "final": "Denied",
                    "message": "No biometric input was provided.",
                },
            ),
        )

    row = get_session(session_id)
    if not row:
        flash("Session not found.")
        return redirect(url_for("main.decrypt_page"))

    try:
        probe, paths = probe_from_fingerprint(
            fp_file,
            face_f,
        )
        auth_analysis = _probe_auth_analysis(session_id, probe, paths)
        if not probe.fingerprint_minutiae and not probe.face_minutiae:
            flash("No biometric features could be extracted.")
            return render_template(
                "decrypt.html",
                **_decrypt_context(
                    sessions,
                    auth_status={
                        "fingerprint": "Failed",
                        "face": "Failed",
                        "final": "Denied",
                        "message": "Feature extraction failed.",
                    },
                    auth_analysis=auth_analysis,
                ),
            )

        package = GroupEncryptedMessage.from_json(row["group_payload"])
        stored_profiles = [
            BiometricProfile.from_json(p["profile_json"]) for p in get_participants(session_id)
        ]
        identified = identify_participant(stored_profiles, probe)
        verify_decrypt_authorization(identified, probe)

        plaintext_bytes, decryptor_name = group_decrypt_by_fingerprint(package, probe)

        content = persist_download(unpack_payload(plaintext_bytes))
        plaintext = content["preview"]
        log_decrypt(session_id, decryptor_name)
        session[f"decrypted_{session_id}"] = {
            "plaintext": plaintext,
            "decryptor_name": decryptor_name,
            "content": content,
        }
        participants = get_participants(session_id)
        identified_row = next(
            (p for p in participants if p["name"].strip().lower() == decryptor_name.strip().lower()),
            None,
        )
        is_encryptor = bool(identified_row and identified_row["is_encryptor"])
        raw_edits = [dict(e) for e in get_message_edits(session_id)]
        readable = _readable_edits(raw_edits)
        original_message = _original_message_text(dict(row), readable, plaintext)
        edits = format_ist_list(readable, "edited_at")
        success_analysis = (
            build_auth_analysis(
                BiometricProfile.from_json(identified_row["profile_json"]),
                probe,
                paths.get("fp_path"),
                paths.get("face_path"),
                decryptor_name,
            )
            if identified_row
            else auth_analysis
        )
        return render_template(
            "decrypt_result.html",
            session_id=session_id,
            label=row["label"],
            decryptor_name=decryptor_name,
            message_plaintext=plaintext,
            content=content,
            original_message=original_message,
            message_edits=edits,
            decrypted_at_ist=format_ist(datetime.utcnow()),
            session_created_ist=format_ist(row["created_at"]),
            is_encryptor=is_encryptor,
            auth_analysis=success_analysis,
        )
    except BiometricValidationError as exc:
        flash(str(exc))
        return render_template(
            "decrypt.html",
            **_decrypt_context(
                sessions,
                auth_status={
                    "fingerprint": "Failed",
                    "face": "Failed",
                    "final": "Denied",
                    "message": str(exc),
                },
            ),
        )
    except PermissionError as exc:
        flash(str(exc))
        analysis = None
        try:
            analysis = _probe_auth_analysis(session_id, probe, paths)
        except Exception:
            analysis = None
        fp_st = "Failed"
        face_st = "Failed"
        if analysis:
            fp_st = analysis["fingerprint_status"]
            face_st = analysis["face_status"]
        return render_template(
            "decrypt.html",
            **_decrypt_context(
                sessions,
                auth_status={
                    "fingerprint": fp_st,
                    "face": face_st,
                    "final": "Denied",
                    "message": str(exc),
                },
                auth_analysis=analysis,
            ),
        )
    except Exception as exc:
        flash(f"Decryption failed: {exc}")
        return redirect(url_for("main.decrypt_page"))


@bp.route("/session/<int:session_id>/edit", methods=["GET", "POST"])
def session_edit(session_id: int):
    """Session management (delete, decryptors): encryptor-only, no time limit."""
    row = get_session(session_id)
    if not row:
        flash("Session not found.")
        return redirect(url_for("main.index"))

    participants = get_participants(session_id)
    decryptors = [dict(p) for p in participants if not p["is_encryptor"]]

    if request.method == "GET":
        return render_template(
            "session_edit.html",
            session_id=session_id,
            session=dict(row),
            decryptors=decryptors,
            max_users=MAX_AUTHORIZED_USERS,
            participant_count=len(participants),
        )

    action = request.form.get("action", "")
    encryptor_name = request.form.get("encryptor_name", "").strip()
    fp_file, face_f = resolve_prefixed_biometrics(request, "encryptor_")

    if not encryptor_name or (not fp_file and not face_f):
        flash("Encryptor name and at least one biometric (fingerprint, face, or both) are required.")
        return redirect(url_for("main.session_edit", session_id=session_id))

    try:
        probe, probe_paths = probe_from_fingerprint(
            fp_file,
            face_f,
        )
        if not verify_encryptor_fingerprint(
            session_id, probe_paths["fp_path"], probe_paths.get("face_path")
        ):
            flash("Only the session encryptor can manage this session (biometric verification failed).")
            return redirect(url_for("main.session_edit", session_id=session_id))

        row = get_session(session_id)
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        admin_plaintext, _ = group_decrypt_by_fingerprint(package, probe, encryptor_only=True)

        if action == "delete":
            delete_session(session_id)
            flash(f"Session #{session_id} deleted.")
            return redirect(url_for("main.index"))

        if action == "add_decryptor":
            new_name = request.form.get("decryptor_name", "").strip()
            new_fp, dec_face = resolve_prefixed_biometrics(request, "decryptor_")
            if not new_name or (not new_fp and not dec_face):
                flash("Decryptor name and at least one biometric (fingerprint, face, or both) are required.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            if dec_face:
                reject_decryptor_face_live(request, "decryptor_")
            profile, meta = profile_from_form(
                new_name,
                new_fp,
                dec_face,
            )
            add_session_decryptor(session_id, {"name": new_name, **meta}, admin_plaintext)
            flash(f"Decryptor '{new_name}' added to session #{session_id}.")
            return redirect(url_for("main.session_edit", session_id=session_id))

        if action == "remove_decryptor":
            remove_name = request.form.get("remove_name", "").strip()
            if not remove_name:
                flash("Select a decryptor to remove.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            remove_session_decryptor(session_id, remove_name, admin_plaintext)
            flash(f"Decryptor '{remove_name}' removed from session #{session_id}.")
            return redirect(url_for("main.session_edit", session_id=session_id))

        flash("Unknown action.")
    except BiometricValidationError as exc:
        flash(str(exc))
    except Exception as exc:
        flash(f"Session update failed: {exc}")

    return redirect(url_for("main.session_edit", session_id=session_id))


def _chat_unlocked(session_id: int) -> bool:
    return bool(session.get(f"chat_unlock_{session_id}"))


def _decrypted_view(session_id: int) -> dict | None:
    return session.get(f"decrypted_{session_id}")


def _clear_chat_access(session_id: int) -> None:
    """Require fresh biometric decrypt before showing message content again."""
    session.pop(f"chat_unlock_{session_id}", None)
    session.pop(f"decrypted_{session_id}", None)


def _clear_all_chat_access() -> None:
    for key in list(session.keys()):
        if key.startswith("chat_unlock_") or key.startswith("decrypted_"):
            session.pop(key, None)


def _readable_edits(edits: list[dict]) -> list[dict]:
    return [
        e
        for e in edits
        if e.get("old_text") not in ("[encrypted]", "", None)
        and e.get("new_text") not in ("[encrypted]", "", None)
    ]


def _original_message_text(row: dict, edits: list[dict], current: str | None) -> str | None:
    original = row.get("original_plaintext")
    if original and original not in ("[encrypted]", ""):
        return original
    readable = _readable_edits(edits)
    if readable:
        return readable[0].get("old_text")
    return current


@bp.route("/chat/<int:session_id>/unlock", methods=["GET", "POST"])
def chat_unlock(session_id: int):
    """Encryptor fingerprint gate before viewing session chat."""
    data = chat_payload(session_id)
    if not data:
        flash("Session not found.")
        return redirect(url_for("main.index"))

    if request.method == "GET":
        return render_template(
            "chat_unlock.html",
            session_id=session_id,
            encryptor_name=data["session"]["encryptor_name"],
            label=data["session"]["label"],
        )

    fp_file, face_f = resolve_prefixed_biometrics(request, "encryptor_")
    if not fp_file and not face_f:
        fp_file, face_f = resolve_prefixed_biometrics(request, "")
    if not fp_file and not face_f:
        flash("Provide encryptor fingerprint, face, or both to open this chat.")
        return redirect(url_for("main.chat_unlock", session_id=session_id))

    try:
        probe, _paths = probe_from_fingerprint(
            fp_file,
            face_f,
        )
        row = get_session(session_id)
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext_bytes, decryptor_name = group_decrypt_by_fingerprint(
            package, probe, encryptor_only=True
        )
        if decryptor_name.strip().lower() != row["encryptor_name"].strip().lower():
            flash("Only the session encryptor can open this chat.")
            return redirect(url_for("main.chat_unlock", session_id=session_id))

        content = persist_download(unpack_payload(plaintext_bytes))
        plaintext = content["preview"]
        session[f"chat_unlock_{session_id}"] = True
        session[f"decrypted_{session_id}"] = {
            "plaintext": plaintext,
            "decryptor_name": decryptor_name,
            "content": content,
        }
        log_decrypt(session_id, decryptor_name)
        flash("Encryptor verified. Message unlocked.")
        return redirect(url_for("main.chat_page", session_id=session_id))
    except BiometricValidationError as exc:
        flash(str(exc))
        return redirect(url_for("main.chat_unlock", session_id=session_id))
    except PermissionError as exc:
        flash(str(exc))
        return redirect(url_for("main.chat_unlock", session_id=session_id))
    except Exception as exc:
        flash(f"Could not unlock chat: {exc}")
        return redirect(url_for("main.chat_unlock", session_id=session_id))


@bp.route("/chat/<int:session_id>")
def chat_page(session_id: int):
    data = chat_payload(session_id)
    if not data:
        flash("Session not found.")
        return redirect(url_for("main.index"))
    data["decrypt_events"] = format_ist_list(data["decrypt_events"], "decrypted_at")
    data["edits"] = format_ist_list(data.get("edits", []), "edited_at")
    row = data["session"]
    editable = can_edit(session_id)
    seconds_left = 0
    if row.get("edit_deadline"):
        deadline = datetime.fromisoformat(row["edit_deadline"])
        seconds_left = max(0, int((deadline - datetime.utcnow()).total_seconds()))

    decrypted_view = _decrypted_view(session_id)
    message_plaintext = None
    decryptor_name = None
    original_message = None
    content = None
    readable_edits = _readable_edits(data.get("edits", []))

    if decrypted_view:
        message_plaintext = decrypted_view["plaintext"]
        decryptor_name = decrypted_view["decryptor_name"]
        content = decrypted_view.get("content")
        original_message = _original_message_text(row, readable_edits, message_plaintext)

    return render_template(
        "chat.html",
        session_id=session_id,
        data=data,
        readable_edits=readable_edits if decrypted_view else [],
        original_message=original_message,
        editable=editable,
        seconds_left=seconds_left,
        edit_window=EDIT_WINDOW_SECONDS,
        message_plaintext=message_plaintext,
        content=content,
        decryptor_name=decryptor_name,
        session_created_ist=format_ist(row.get("created_at")),
        message_locked=not bool(decrypted_view),
    )


@bp.route("/chat/<int:session_id>/edit", methods=["POST"])
def edit_message(session_id: int):
    """Encrypted message body only — 5-minute window after encryption."""
    if not can_edit(session_id):
        flash(
            "Encrypted message edit window expired (5 minutes). "
            "You can still manage the session or decrypt anytime."
        )
        return redirect(url_for("main.chat_page", session_id=session_id))

    row = get_session(session_id)
    if not row:
        flash("Session not found.")
        return redirect(url_for("main.index"))

    new_text = request.form.get("new_text", "").strip()
    fp_file, face_f = resolve_prefixed_biometrics(request, "encryptor_")
    if not fp_file and not face_f:
        fp_file, face_f = resolve_prefixed_biometrics(request, "")
    if not fp_file and not face_f:
        flash("Encryptor biometrics (fingerprint, face, or both) are required.")
        return redirect(url_for("main.chat_page", session_id=session_id))

    try:
        probe, _ = probe_from_fingerprint(
            fp_file,
            face_f,
        )
        package_existing = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext_bytes, _ = group_decrypt_by_fingerprint(
            package_existing, probe, encryptor_only=True
        )
        old_payload = unpack_payload(plaintext_bytes)
        updated = replace_text(old_payload, new_text)
        old_text = preview_text(old_payload)
        new_preview = preview_text(updated)

        participants_db = get_participants(session_id)
        profiles = [BiometricProfile.from_json(p["profile_json"]) for p in participants_db]
        package = group_encrypt(pack_payload(updated), profiles)
        update_message(session_id, package.to_json(), old_text, new_preview)
        invalidate(session_id)
        _clear_chat_access(session_id)
        flash(
            "Message updated and re-encrypted. Verify biometrics again to read the new content."
        )
    except BiometricValidationError as exc:
        flash(str(exc))
    except Exception as exc:
        flash(f"Edit failed: {exc}")
    return redirect(url_for("main.chat_unlock", session_id=session_id))


@bp.route("/chat/<int:session_id>/analysis")
def chat_analysis(session_id: int):
    data = chat_payload(session_id)
    if not data:
        flash("Session not found.")
        return redirect(url_for("main.index"))

    participants = data["participants"]
    encryptor = next((p for p in participants if p["is_encryptor"]), participants[0] if participants else None)
    decrypt_names = [d["decryptor_name"] for d in data["decrypt_events"]]

    encryptor_profile = BiometricProfile.from_json(encryptor["profile_json"]) if encryptor else None
    encryptor_panel = None
    if encryptor and encryptor_profile:
        encryptor_panel = dashboard_biometric_panel(
            encryptor_profile,
            encryptor["fp_path"],
            "Encrypting Person",
            encryptor.get("iris_path"),
            encryptor.get("face_path"),
            session_id=session_id,
        )

    analysis_data = dict(data)
    analysis_data["decrypt_events"] = format_ist_list(
        analysis_data["decrypt_events"],
        "decrypted_at",
    )
    analysis_data["edits"] = format_ist_list(analysis_data.get("edits", []), "edited_at")

    decryptor_panels: list[dict] = []
    decrypt_events = analysis_data.get("decrypt_events", [])
    for p in participants:
        if p["is_encryptor"]:
            continue
        prof = BiometricProfile.from_json(p["profile_json"])
        pname = p["name"]
        events_for_user = [e for e in decrypt_events if e.get("decryptor_name") == pname]
        panel = dashboard_biometric_panel(
            prof,
            p["fp_path"],
            "Authorized Decryptor",
            p.get("iris_path"),
            p.get("face_path"),
            session_id=session_id,
        )
        panel.update(
            {
                "slot": p.get("slot", "—"),
                "role": "Authorized Decryptor",
                "access_level": "BIOMETRIC-GATED",
                "decrypt_count": len(events_for_user),
                "last_access": events_for_user[-1]["decrypted_at"] if events_for_user else "Never",
                "status": "ACTIVE" if events_for_user else "ENROLLED",
                "face_minutiae": len(prof.face_minutiae),
                "fingerprint_minutiae": len(prof.fingerprint_minutiae),
                "multimodal": bool(prof.face_minutiae and prof.fingerprint_minutiae),
                "face_landmarks": len(prof.face_minutiae),
            }
        )
        decryptor_panels.append(panel)

    unique_decryptors: list[str] = []
    for n in decrypt_names:
        if n not in unique_decryptors:
            unique_decryptors.append(n)

    package = GroupEncryptedMessage.from_json(data["session"]["group_payload"])
    run_and_cache(session_id, force=True)
    metrics = session_security_metrics(package.message_ciphertext)

    return render_template(
        "chat_analysis.html",
        session_id=session_id,
        data=analysis_data,
        encryptor_panel=encryptor_panel,
        decryptor_panels=decryptor_panels,
        encryptor_name=encryptor["name"] if encryptor else data["session"]["encryptor_name"],
        decrypt_names=decrypt_names,
        unique_decryptors=unique_decryptors,
        authorized_names=[p["name"] for p in participants],
        edit_window=EDIT_WINDOW_SECONDS,
        session_created_ist=format_ist(data["session"].get("created_at")),
        **metrics,
    )


@bp.route("/download/<token>")
def download_content(token):
    view = None
    for key, value in session.items():
        if not str(key).startswith("decrypted_"):
            continue
        content = (value or {}).get("content") if isinstance(value, dict) else None
        if content and content.get("token") == token:
            view = content
            break
    if not view or not view.get("path"):
        flash("Download is not available. Decrypt the session again.")
        return redirect(url_for("main.index"))
    from pathlib import Path

    path = Path(view["path"])
    if not path.is_file():
        flash("Downloaded file expired. Decrypt again.")
        return redirect(url_for("main.index"))
    as_attachment = request.args.get("download") == "1"
    return send_file(
        path,
        as_attachment=as_attachment,
        download_name=view.get("filename") or path.name,
        mimetype=view.get("mime") or "application/octet-stream",
    )


@bp.route("/analysis", methods=["GET", "POST"])
def analysis_page():
    sessions = list_sessions()
    if request.method == "GET":
        return render_template("analysis.html", sessions=sessions)
    session_id = request.form.get("session_id", type=int)
    if session_id:
        return redirect(url_for("main.chat_analysis", session_id=session_id))
    flash("Select a session for chat/form analysis.")
    return redirect(url_for("main.analysis_page"))


@bp.route("/api/health")
def health():
    return jsonify({"status": "ok", "system": "QSBAC", "max_users": MAX_AUTHORIZED_USERS})


@bp.route("/api/fingerprint/sensor_scan", methods=["POST"])
def api_fingerprint_sensor_scan():
    """Live scan from a USB fingerprint sensor. Never uses the face webcam."""
    from qsbas.fingerprint_sensor import capture_fingerprint_sensor, frame_to_png_data_url

    try:
        ok, message, frame = capture_fingerprint_sensor()
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Fingerprint sensor error: {exc}"}), 500
    if not ok or frame is None:
        return jsonify({"ok": False, "error": message}), 404
    return jsonify({"ok": True, "device": message, "image": frame_to_png_data_url(frame)})


def _benchmark_or_404(session_id: int):
    row = get_session(session_id)
    if not row:
        return None, (jsonify({"error": "Session not found"}), 404)
    return run_and_cache(session_id), None


@bp.route("/api/live_metrics/<int:session_id>")
def api_live_metrics(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(data)


@bp.route("/api/benchmark_results/<int:session_id>")
def api_benchmark_results(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(
        {
            "session_id": session_id,
            "comparison": data["comparison"],
            "algorithms": data["algorithms"],
            "elapsed_ms": data["elapsed_ms"],
            "timestamp": data["timestamp"],
        }
    )


@bp.route("/api/entropy_stream/<int:session_id>")
def api_entropy_stream(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(
        {
            "labels": data["comparison"]["labels"],
            "entropy": data["comparison"]["entropy"],
            "history": data.get("history", []),
        }
    )


@bp.route("/api/telemetry/<int:session_id>")
def api_telemetry(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    payload = chat_payload(session_id)
    primary = data.get("primary", {})
    return jsonify(
        {
            "session_id": session_id,
            "entropy": primary.get("entropy", 0),
            "nist_pass_rate": primary.get("nist_pass_rate", 0),
            "avalanche_ratio": primary.get("avalanche_ratio", 0),
            "security_stress": primary.get("security_stress", 0),
            "security_rating": primary.get("security_rating", "N/A"),
            "qsbac_telemetry": data.get("qsbac_telemetry", {}),
            "decrypt_events": len(payload.get("decrypt_events", [])) if payload else 0,
            "attack_simulation": data.get("attack_simulation", {}),
            "comparison": data["comparison"],
        }
    )


@bp.route("/api/security_analysis/<int:session_id>")
def api_security_analysis(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(data.get("research", {}))


@bp.route("/api/attack_simulation/<int:session_id>")
def api_attack_simulation(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(data.get("attack_simulation", {}))


@bp.route("/api/sbox/<int:session_id>")
def api_sbox(session_id: int):
    data, err = _benchmark_or_404(session_id)
    if err:
        return err
    return jsonify(data.get("sbox", {}))


@bp.route("/api/benchmark_refresh/<int:session_id>", methods=["POST"])
def api_benchmark_refresh(session_id: int):
    row = get_session(session_id)
    if not row:
        return jsonify({"error": "Session not found"}), 404
    invalidate(session_id)
    data = run_and_cache(session_id, force=True)
    return jsonify({"ok": True, "elapsed_ms": data["elapsed_ms"]})
