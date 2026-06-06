"""OAuth callback: bridge django-allauth session to lokdown JWT / pre-2FA session."""

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
    After Google/GitHub OAuth, issue lokdown tokens or a pending 2FA session_id.

    ?format=json returns raw JSON (for API clients). Default is an HTML debug page.
    Same logic as GET /api/auth/oauth/callback.
    """
    try:
        payload = bridge_oauth_session_to_lokdown(request.user, request)
    except RuntimeError:
        return HttpResponse("Failed to create lokdown authentication session", status=500)

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
