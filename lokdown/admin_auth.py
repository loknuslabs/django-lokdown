import json

from django.conf import settings
from django.contrib import messages
from django.contrib.admin import site as admin_site
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render

from lokdown.helpers.auth_flow_helper import (
    begin_passkey_registration,
    begin_totp_setup,
    complete_passkey_registration,
    complete_totp_setup,
    create_authentication_session,
    validate_session_data,
    verify_admin_second_factor,
)
from lokdown.helpers.backup_codes_helper import (
    get_or_create_backup_codes,
    user_backup_codes_exist,
)
from lokdown.helpers.passkey_helper import has_passkey_enabled
from lokdown.helpers.totp_helper import (
    get_or_create_totp,
    has_totp_enabled,
)
from lokdown.helpers.twofa_helper import get_available_2fa_methods, is_2fa_enabled


def _admin_2fa_required() -> bool:
    return getattr(settings, "ADMIN_2FA_REQUIRED", False)


def admin_login_view(request):
    """Custom admin login with optional 2FA."""
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user is None or not user.is_staff:
            messages.error(request, "Invalid credentials or insufficient permissions.")
        elif not _admin_2fa_required():
            login(request, user)
            return redirect("admin:index")
        else:
            available_methods = get_available_2fa_methods(user)
            has_2fa = any(available_methods.values())
            session_id = create_authentication_session(user, request)
            if not session_id:
                messages.error(request, "Failed to create authentication session.")
                return redirect("admin_login")

            request.session["admin_2fa_session_id"] = session_id
            if not has_2fa:
                return redirect("admin_2fa_setup")
            return redirect("admin_2fa_verify")

    return admin_site.login(request)


def _get_admin_pending_session(request):
    session_id = request.session.get("admin_2fa_session_id")
    session, _error = validate_session_data(session_id)
    return session


def admin_2fa_setup_view(request):
    session = _get_admin_pending_session(request)
    if not session:
        return redirect("admin_login")

    user = session.user
    if not has_totp_enabled(user) and has_passkey_enabled(user):
        user.passkey_credentials.all().delete()

    if request.method == "POST":
        setup_type = request.POST.get("setup_type")
        if setup_type == "totp":
            payload = begin_totp_setup(user)
            return render(
                request,
                "2fa_setup_totp.html",
                {"qr_code": payload["qr_code"], "secret": payload["secret"]},
            )
        if setup_type == "passkey":
            return redirect("admin_2fa_setup_passkey")

    return render(request, "2fa_setup.html")


def admin_2fa_verify_view(request):
    session = _get_admin_pending_session(request)
    if not session:
        messages.error(request, "Invalid or expired session.")
        return redirect("admin_login")

    user = session.user
    if not is_2fa_enabled(user):
        return redirect("admin_2fa_setup")

    available_methods = []
    if has_totp_enabled(user):
        available_methods.append("totp")
    if has_passkey_enabled(user):
        available_methods.append("passkey")
    if user_backup_codes_exist(user):
        available_methods.append("backup")

    if request.method == "POST":
        ok, error = verify_admin_second_factor(
            session,
            request.POST.get("totp_token"),
            request.POST.get("passkey_response"),
            request.POST.get("backup_code"),
            request,
        )
        if ok:
            login(request, user)
            del request.session["admin_2fa_session_id"]
            return redirect("admin:index")
        messages.error(request, error or "Invalid 2FA token.")

    return render(
        request,
        "2fa_verify.html",
        {"available_methods": available_methods, "user": user},
    )


def admin_2fa_verify_totp_setup(request):
    session = _get_admin_pending_session(request)
    if not session:
        return redirect("admin_login")

    if request.method == "POST":
        totp_token = request.POST.get("totp_token")
        ok, error, _backup_codes = complete_totp_setup(session.user, totp_token)
        if ok:
            messages.success(request, "TOTP setup completed successfully!")
            return redirect("admin_2fa_backup_codes")
        messages.error(request, error or "Invalid TOTP token.")

    return redirect("admin_2fa_setup")


def admin_2fa_setup_passkey_view(request):
    session = _get_admin_pending_session(request)
    if not session:
        return redirect("admin_login")

    user = session.user

    if request.method == "POST":
        passkey_response = request.POST.get("passkey_response")
        if passkey_response:
            ok, error, _backup_codes = complete_passkey_registration(
                user,
                session.session_id,
                passkey_response,
                create_backup_codes_if_missing=True,
                request=request,
            )
            if ok:
                messages.success(request, "Passkey setup completed successfully!")
                return redirect("admin_2fa_backup_codes")
            messages.error(request, error or "Passkey setup failed.")

    result = begin_passkey_registration(user, request)
    if not isinstance(result, dict):
        messages.error(request, "Failed to generate passkey options.")
        return redirect("admin_2fa_setup")

    request.session["admin_2fa_session_id"] = result["session_id"]
    return render(
        request,
        "2fa_setup_passkey.html",
        {
            "options": json.dumps(result["options"]),
            "session_id": result["session_id"],
        },
    )


def admin_current_user_totp_setup(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return redirect("admin_login" if _admin_2fa_required() else "admin:login")

    user = request.user
    get_or_create_totp(user)

    if request.method == "POST":
        ok, error, _backup_codes = complete_totp_setup(user, request.POST.get("totp_code"))
        if ok:
            messages.success(request, "TOTP setup completed successfully!")
            return redirect("admin_current_user_backup_codes")
        messages.error(request, error or "Invalid TOTP code.")

    if has_totp_enabled(user):
        messages.error(request, "TOTP is already enabled.")
        return redirect("admin:lokdown_usertimebasedonetimepasswords_changelist")

    payload = begin_totp_setup(user)
    return render(
        request,
        "2fa_setup_totp.html",
        {
            "qr_code": payload["qr_code"],
            "secret": payload["secret"],
            "user": user,
            "is_current_user": True,
        },
    )


def admin_current_user_passkey_setup(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return redirect("admin_login" if _admin_2fa_required() else "admin:login")

    user = request.user

    if request.method == "POST":
        passkey_response = request.POST.get("passkey_response")
        session_id = request.session.get("current_user_passkey_session_id")
        if not session_id:
            messages.error(request, "Session expired. Please try again.")
            return redirect("admin_current_user_passkey_setup")

        ok, error, _backup_codes = complete_passkey_registration(
            user,
            session_id,
            passkey_response,
            create_backup_codes_if_missing=True,
            request=request,
        )
        if ok:
            del request.session["current_user_passkey_session_id"]
            messages.success(request, "Passkey setup completed successfully!")
            return redirect("admin_current_user_backup_codes")
        messages.error(request, error or "Passkey setup failed.")

    result = begin_passkey_registration(user, request)
    if not isinstance(result, dict):
        messages.error(request, "Failed to generate passkey options.")
        return redirect("admin:lokdown_passkeycredential_changelist")

    request.session["current_user_passkey_session_id"] = result["session_id"]
    return render(
        request,
        "2fa_setup_passkey.html",
        {
            "options": json.dumps(result["options"]),
            "user": user,
            "is_current_user": True,
        },
    )


def admin_current_user_backup_codes(request):
    if not request.user.is_authenticated or not request.user.is_staff:
        return redirect("admin_login" if _admin_2fa_required() else "admin:login")

    if request.method == "POST":
        messages.success(request, "2FA setup completed successfully!")
        return redirect("admin:lokdown_passkeycredential_changelist")

    if not user_backup_codes_exist(request.user):
        messages.error(request, "No backup codes found. Please complete 2FA setup first.")
        return redirect("admin:lokdown_usertimebasedonetimepasswords_changelist")

    backup_codes_obj = get_or_create_backup_codes(request.user)
    return render(
        request,
        "2fa_backup_codes.html",
        {
            "backup_codes": backup_codes_obj.codes,
            "user": request.user,
            "is_current_user": True,
        },
    )


def admin_2fa_backup_codes_view(request):
    session = _get_admin_pending_session(request)
    if not session:
        return redirect("admin_login")

    if not user_backup_codes_exist(session.user):
        return redirect("admin_2fa_setup")

    backup_codes_obj = get_or_create_backup_codes(session.user)
    if request.method == "POST":
        return redirect("admin:index")

    return render(
        request,
        "2fa_backup_codes.html",
        {"backup_codes": backup_codes_obj.codes, "user": session.user},
    )
