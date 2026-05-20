"""Flask routes: group encrypt/decrypt, chat, edits, dashboard analysis."""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

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
from app.services import dashboard_biometric_panel, probe_from_fingerprint, profile_from_form, save_upload
from app.session_metrics import session_security_metrics
from app.timefmt import format_ist, format_ist_list
from qsbas.biometric_profile import BiometricProfile, build_profile
from qsbas.biometric_validation import BiometricValidationError
from qsbas.constants import EDIT_WINDOW_SECONDS, MAX_AUTHORIZED_USERS
from qsbas.group_cipher import GroupEncryptedMessage, group_decrypt_by_fingerprint, group_encrypt
from qsbas.cipher import QSBACCipher

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
    plaintext = request.form.get("plaintext", "").strip()
    encryptor_name = request.form.get("encryptor_name", "").strip()

    if not plaintext or not encryptor_name:
        flash("Encryptor name and message are required.")
        return redirect(url_for("main.encrypt_page"))

    enc_fp = request.files.get("encryptor_fingerprint")
    if not enc_fp or not enc_fp.filename:
        flash("Encryptor fingerprint is required.")
        return redirect(url_for("main.encrypt_page"))

    try:
        participants: list[BiometricProfile] = []
        participant_meta: list[dict] = []

        enc_profile, enc_meta = profile_from_form(
            encryptor_name,
            enc_fp,
            request.files.get("encryptor_iris"),
            request.files.get("encryptor_face"),
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
            fp = request.files.get(f"user{slot}_fingerprint")
            if not name or not fp or not fp.filename:
                flash("Each added decryptor needs a name and fingerprint.")
                return redirect(url_for("main.encrypt_page"))
            profile, meta = profile_from_form(
                name,
                fp,
                request.files.get(f"user{slot}_iris"),
                request.files.get(f"user{slot}_face"),
            )
            participants.append(profile)
            participant_meta.append({"slot": len(participant_meta), "name": name, "is_encryptor": False, **meta})

        package = group_encrypt(plaintext.encode("utf-8"), participants)
        session_id = save_group_session(
            label,
            encryptor_name,
            package.to_json(),
            enc_meta["fp_path"],
            participant_meta,
            original_plaintext=plaintext,
        )
        session.pop(f"chat_unlock_{session_id}", None)
        session.pop(f"decrypted_{session_id}", None)
        flash(
            f"Encrypted for {len(participants)} authorized user(s). Session #{session_id}. "
            "Message is hidden until a valid user decrypts with their own fingerprint."
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


@bp.route("/decrypt", methods=["GET", "POST"])
def decrypt_page():
    sessions = list_sessions()
    if request.method == "GET":
        return render_template(
            "decrypt.html",
            sessions=sessions,
            authorized_map=_session_authorized_map(),
            max_users=MAX_AUTHORIZED_USERS,
        )

    session_id = request.form.get("session_id", type=int)
    fp_file = request.files.get("fingerprint")

    if not session_id or not fp_file or not fp_file.filename:
        flash("Session and your fingerprint are required.")
        return redirect(url_for("main.decrypt_page"))

    row = get_session(session_id)
    if not row:
        flash("Session not found.")
        return redirect(url_for("main.decrypt_page"))

    try:
        iris_f = request.files.get("iris")
        face_f = request.files.get("face")
        probe, _paths = probe_from_fingerprint(
            fp_file,
            iris_f if iris_f and iris_f.filename else None,
            face_f if face_f and face_f.filename else None,
        )
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext_bytes, decryptor_name = group_decrypt_by_fingerprint(package, probe)
        plaintext = plaintext_bytes.decode("utf-8", errors="replace")
        log_decrypt(session_id, decryptor_name)
        session[f"decrypted_{session_id}"] = {
            "plaintext": plaintext,
            "decryptor_name": decryptor_name,
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
        return render_template(
            "decrypt_result.html",
            session_id=session_id,
            label=row["label"],
            decryptor_name=decryptor_name,
            message_plaintext=plaintext,
            original_message=original_message,
            message_edits=edits,
            decrypted_at_ist=format_ist(datetime.utcnow()),
            session_created_ist=format_ist(row["created_at"]),
            is_encryptor=is_encryptor,
        )
    except BiometricValidationError as exc:
        flash(str(exc))
        return redirect(url_for("main.decrypt_page"))
    except PermissionError as exc:
        flash(str(exc))
        return redirect(url_for("main.decrypt_page"))
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
    fp_file = request.files.get("encryptor_fingerprint")

    if not encryptor_name or not fp_file or not fp_file.filename:
        flash("Encryptor name and fingerprint are required to manage this session.")
        return redirect(url_for("main.session_edit", session_id=session_id))

    try:
        iris_f = request.files.get("encryptor_iris")
        face_f = request.files.get("encryptor_face")
        probe, probe_paths = probe_from_fingerprint(
            fp_file,
            iris_f if iris_f and iris_f.filename else None,
            face_f if face_f and face_f.filename else None,
        )
        if not verify_encryptor_fingerprint(session_id, probe_paths["fp_path"]):
            flash("Only the session encryptor can manage this session (fingerprint verification failed).")
            return redirect(url_for("main.session_edit", session_id=session_id))

        row = get_session(session_id)
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        admin_plaintext, _ = group_decrypt_by_fingerprint(package, probe, encryptor_only=True)
        admin_plain = admin_plaintext.decode("utf-8", errors="replace")

        if action == "delete":
            delete_session(session_id)
            flash(f"Session #{session_id} deleted.")
            return redirect(url_for("main.index"))

        if action == "add_decryptor":
            new_name = request.form.get("decryptor_name", "").strip()
            new_fp = request.files.get("decryptor_fingerprint")
            dec_iris = request.files.get("decryptor_iris")
            dec_face = request.files.get("decryptor_face")
            if not new_name or not new_fp or not new_fp.filename:
                flash("Decryptor name and fingerprint are required.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            profile, meta = profile_from_form(
                new_name,
                new_fp,
                dec_iris if dec_iris and dec_iris.filename else None,
                dec_face if dec_face and dec_face.filename else None,
            )
            add_session_decryptor(session_id, {"name": new_name, **meta}, admin_plain)
            flash(f"Decryptor '{new_name}' added to session #{session_id}.")
            return redirect(url_for("main.session_edit", session_id=session_id))

        if action == "remove_decryptor":
            remove_name = request.form.get("remove_name", "").strip()
            if not remove_name:
                flash("Select a decryptor to remove.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            remove_session_decryptor(session_id, remove_name, admin_plain)
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

    fp_file = request.files.get("encryptor_fingerprint") or request.files.get("fingerprint")
    if not fp_file or not fp_file.filename:
        flash("Encryptor fingerprint is required to open this chat.")
        return redirect(url_for("main.chat_unlock", session_id=session_id))

    try:
        iris_f = request.files.get("encryptor_iris") or request.files.get("iris")
        face_f = request.files.get("encryptor_face") or request.files.get("face")
        probe, _paths = probe_from_fingerprint(
            fp_file,
            iris_f if iris_f and iris_f.filename else None,
            face_f if face_f and face_f.filename else None,
        )
        row = get_session(session_id)
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext_bytes, decryptor_name = group_decrypt_by_fingerprint(
            package, probe, encryptor_only=True
        )
        if decryptor_name.strip().lower() != row["encryptor_name"].strip().lower():
            flash("Only the session encryptor can open this chat.")
            return redirect(url_for("main.chat_unlock", session_id=session_id))

        plaintext = plaintext_bytes.decode("utf-8", errors="replace")
        session[f"chat_unlock_{session_id}"] = True
        session[f"decrypted_{session_id}"] = {
            "plaintext": plaintext,
            "decryptor_name": decryptor_name,
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
    readable_edits = _readable_edits(data.get("edits", []))

    if decrypted_view:
        message_plaintext = decrypted_view["plaintext"]
        decryptor_name = decrypted_view["decryptor_name"]
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
    fp_file = request.files.get("encryptor_fingerprint") or request.files.get("fingerprint")
    if not new_text or not fp_file or not fp_file.filename:
        flash("Encryptor fingerprint and new message are required.")
        return redirect(url_for("main.chat_page", session_id=session_id))

    try:
        iris_f = request.files.get("encryptor_iris") or request.files.get("iris")
        face_f = request.files.get("encryptor_face") or request.files.get("face")
        probe, _ = probe_from_fingerprint(
            fp_file,
            iris_f if iris_f and iris_f.filename else None,
            face_f if face_f and face_f.filename else None,
        )
        package_existing = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext_bytes, _ = group_decrypt_by_fingerprint(
            package_existing, probe, encryptor_only=True
        )
        old_text = plaintext_bytes.decode("utf-8", errors="replace")

        participants_db = get_participants(session_id)
        profiles = [BiometricProfile.from_json(p["profile_json"]) for p in participants_db]
        package = group_encrypt(new_text.encode("utf-8"), profiles)
        update_message(session_id, package.to_json(), old_text, new_text)
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
    if not _chat_unlocked(session_id):
        return redirect(url_for("main.chat_unlock", session_id=session_id))

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

    decryptor_panels: list[dict] = []
    for p in participants:
        if p["is_encryptor"]:
            continue
        prof = BiometricProfile.from_json(p["profile_json"])
        decryptor_panels.append(
            dashboard_biometric_panel(
                prof,
                p["fp_path"],
                "Authorized Decryptor",
                p.get("iris_path"),
                p.get("face_path"),
                session_id=session_id,
            )
        )

    unique_decryptors: list[str] = []
    for n in decrypt_names:
        if n not in unique_decryptors:
            unique_decryptors.append(n)

    package = GroupEncryptedMessage.from_json(data["session"]["group_payload"])
    metrics = session_security_metrics(package.message_ciphertext)
    analysis_data = dict(data)
    analysis_data["decrypt_events"] = format_ist_list(
        analysis_data["decrypt_events"],
        "decrypted_at",
    )
    analysis_data["edits"] = format_ist_list(analysis_data.get("edits", []), "edited_at")

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
    return {"status": "ok", "system": "QSBAC", "max_users": MAX_AUTHORIZED_USERS}
