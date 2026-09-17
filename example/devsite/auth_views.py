"""OAuth callback: bridge django-allauth session to lokdown JWTs (no 2FA step)."""

import json

from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.http import require_GET

from lokdown.control.socialauth_controller import bridge_oauth_session_to_lokdown


@login_required
@require_GET
def auth_callback(request):
    """
    After Google/GitHub OAuth, issue lokdown JWTs (no TOTP, backup, or passkey step).

    ?format=json returns raw JSON (for API clients). Default is an HTML debug page.
    Same logic as POST /api/auth/oauth/callback.
    """
    try:
        payload = bridge_oauth_session_to_lokdown(request.user, request)
    except RuntimeError:
        return HttpResponse("Failed to issue lokdown authentication tokens", status=500)

    if request.GET.get("format") == "json":
        return HttpResponse(
            json.dumps(payload, indent=2),
            content_type="application/json",
        )

    return render(
        request,
        "devsite/auth_callback.html",
        {
            "payload": payload,
            "payload_json": json.dumps(payload, indent=2),
            "user": request.user,
            "requires_2fa": payload.get("requires_2fa"),
        },
    )
