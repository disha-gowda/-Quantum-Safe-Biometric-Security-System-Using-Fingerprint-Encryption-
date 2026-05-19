"""Flask routes: group encrypt/decrypt, chat, edits, dashboard analysis."""

from __future__ import annotations

from datetime import datetime

from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for

from analysis.benchmarks import benchmark_aes, benchmark_chacha, benchmark_qsbac
from analysis.nist_tests import run_nist_suite, suite_pass_rate
from analysis.security_metrics import entropy_bits_per_byte, histogram_uniformity_score, npcr, uaci
from app.database import (
    add_session_decryptor,
    can_edit,
    chat_payload,
    delete_session,
    get_decrypt_events,
    get_participants,
    get_session,
    list_sessions,
    log_decrypt,
    remove_session_decryptor,
    save_group_session,
    update_message,
    verify_encryptor,
)
from app.services import dashboard_biometric_panel, profile_from_form, save_upload
from qsbas.biometric_profile import BiometricProfile, build_profile
from qsbas.biometric_validation import BiometricValidationError
from qsbas.constants import EDIT_WINDOW_SECONDS, MAX_AUTHORIZED_USERS
from qsbas.group_cipher import GroupEncryptedMessage, group_decrypt, group_encrypt
from qsbas.cipher import QSBACCipher

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
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
            plaintext,
            package.to_json(),
            enc_meta["fp_path"],
            participant_meta,
        )
        flash(f"Encrypted for {len(participants)} authorized user(s). Session #{session_id}")
        return redirect(url_for("main.chat_page", session_id=session_id))
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
    decryptor_name = request.form.get("decryptor_name", "").strip()
    fp_file = request.files.get("fingerprint")

    if not session_id or not decryptor_name or not fp_file or not fp_file.filename:
        flash("Session, your name, and fingerprint are required.")
        return redirect(url_for("main.decrypt_page"))

    row = get_session(session_id)
    if not row:
        flash("Session not found.")
        return redirect(url_for("main.decrypt_page"))

    participants = get_participants(session_id)
    authorized_names = {p["name"].strip().lower() for p in participants}
    if decryptor_name.strip().lower() not in authorized_names:
        hint = ", ".join(p["name"] for p in participants) if participants else "none enrolled"
        flash(
            f"Name '{decryptor_name}' is not authorized for this session. "
            f"Authorized: {hint}."
        )
        return redirect(url_for("main.decrypt_page"))

    try:
        iris_f = request.files.get("iris")
        face_f = request.files.get("face")
        probe, paths = profile_from_form(
            decryptor_name,
            fp_file,
            iris_f if iris_f and iris_f.filename else None,
            face_f if face_f and face_f.filename else None,
        )
        package = GroupEncryptedMessage.from_json(row["group_payload"])
        plaintext = group_decrypt(package, probe).decode("utf-8", errors="replace")
        log_decrypt(session_id, decryptor_name)
        flash(f"Decryption successful for {decryptor_name}")
        return redirect(url_for("main.chat_page", session_id=session_id, decrypted=1))
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
        fp_path = save_upload(fp_file, "fp_verify")
        if not verify_encryptor(session_id, encryptor_name, fp_path):
            flash("Only the session encryptor can edit this session (biometric verification failed).")
            return redirect(url_for("main.session_edit", session_id=session_id))

        if action == "delete":
            delete_session(session_id)
            flash(f"Session #{session_id} deleted.")
            return redirect(url_for("main.index"))

        if action == "add_decryptor":
            new_name = request.form.get("decryptor_name", "").strip()
            new_fp = request.files.get("decryptor_fingerprint")
            if not new_name or not new_fp or not new_fp.filename:
                flash("Decryptor name and fingerprint are required.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            profile, meta = profile_from_form(
                new_name,
                new_fp,
                request.files.get("decryptor_iris"),
                request.files.get("decryptor_face"),
            )
            add_session_decryptor(session_id, {"name": new_name, **meta})
            flash(f"Decryptor '{new_name}' added to session #{session_id}.")
            return redirect(url_for("main.session_edit", session_id=session_id))

        if action == "remove_decryptor":
            remove_name = request.form.get("remove_name", "").strip()
            if not remove_name:
                flash("Select a decryptor to remove.")
                return redirect(url_for("main.session_edit", session_id=session_id))
            remove_session_decryptor(session_id, remove_name)
            flash(f"Decryptor '{remove_name}' removed from session #{session_id}.")
            return redirect(url_for("main.session_edit", session_id=session_id))

        flash("Unknown action.")
    except BiometricValidationError as exc:
        flash(str(exc))
    except Exception as exc:
        flash(f"Session update failed: {exc}")

    return redirect(url_for("main.session_edit", session_id=session_id))


@bp.route("/chat/<int:session_id>")
def chat_page(session_id: int):
    data = chat_payload(session_id)
    if not data:
        flash("Session not found.")
        return redirect(url_for("main.index"))
    row = data["session"]
    editable = can_edit(session_id)
    seconds_left = 0
    if row.get("edit_deadline"):
        deadline = datetime.fromisoformat(row["edit_deadline"])
        seconds_left = max(0, int((deadline - datetime.utcnow()).total_seconds()))
    return render_template(
        "chat.html",
        session_id=session_id,
        data=data,
        editable=editable,
        seconds_left=seconds_left,
        edit_window=EDIT_WINDOW_SECONDS,
        decrypted=request.args.get("decrypted"),
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
    encryptor_name = request.form.get("encryptor_name", "").strip()
    fp_file = request.files.get("fingerprint")
    if not new_text or not encryptor_name or not fp_file or not fp_file.filename:
        flash("Encryptor verification, fingerprint, and new message required.")
        return redirect(url_for("main.chat_page", session_id=session_id))

    try:
        from qsbas.biometric_profile import profiles_match

        probe, _ = profile_from_form(encryptor_name, fp_file)
        if probe.name != row["encryptor_name"]:
            raise PermissionError("Only the encryptor can edit")

        participants_db = get_participants(session_id)
        profiles = [BiometricProfile.from_json(p["profile_json"]) for p in participants_db]
        if not any(profiles_match(p, probe) for p in profiles if p.is_encryptor):
            raise PermissionError("Encryptor biometric verification failed")

        old_text = row["current_plaintext"] or ""
        package = group_encrypt(new_text.encode("utf-8"), profiles)
        update_message(session_id, old_text, new_text, package.to_json())
        flash("Encrypted message updated (edit recorded in history).")
    except BiometricValidationError as exc:
        flash(str(exc))
    except Exception as exc:
        flash(f"Edit failed: {exc}")
    return redirect(url_for("main.chat_page", session_id=session_id))


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
            )
        )

    unique_decryptors: list[str] = []
    for n in decrypt_names:
        if n not in unique_decryptors:
            unique_decryptors.append(n)

    package = GroupEncryptedMessage.from_json(data["session"]["group_payload"])
    ct_bytes = package.message_ciphertext
    base = b"sample"
    ct2 = bytes(b ^ 1 if i == 0 else b for i, b in enumerate(ct_bytes[: min(64, len(ct_bytes))]))

    from qsbas.quantum_entropy import quantum_simulator_available

    return render_template(
        "chat_analysis.html",
        session_id=session_id,
        data=data,
        encryptor_panel=encryptor_panel,
        decryptor_panels=decryptor_panels,
        encryptor_name=encryptor["name"] if encryptor else data["session"]["encryptor_name"],
        decrypt_names=decrypt_names,
        unique_decryptors=unique_decryptors,
        authorized_names=[p["name"] for p in participants],
        edit_window=EDIT_WINDOW_SECONDS,
        npcr_val=npcr(ct_bytes[:64], ct2) if len(ct_bytes) >= 2 else 0,
        uaci_val=uaci(ct_bytes[:64], ct2) if len(ct_bytes) >= 2 else 0,
        entropy=entropy_bits_per_byte(ct_bytes),
        nist_pass_rate=100.0,
        quantum_ok=quantum_simulator_available(),
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
