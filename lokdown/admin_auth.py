import json
import uuid
import base64
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.shortcuts import render, redirect
from django.utils import timezone
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema, OpenApiResponse

from .helpers.backup_codes_helper import (
    verify_backup_code,
    get_or_create_backup_codes,
    generate_backup_codes,
    has_backup_codes,
)
from .helpers.passkey_helper import verify_passkey, custom_generate_authentication_options
from .helpers.session_helper import (
    create_authentication_session,
    validate_session_data,
)
from .helpers.totp_helper import (
    generate_totp_secret,
    generate_totp_qr_code,
    verify_totp_login,
    verify_totp_token_setup,
    setup_totp_complete,
    get_or_create_2fa,
)
from .models import LoginSession
from .views import (
    is_2fa_enabled,
    has_totp_enabled,
    has_passkey_enabled,
)
from lokdown.helpers.twofa_helper import (
    get_available_2fa_methods,
)
from .helpers.common_helper import get_client_ip
from .serializers import AdminAuthOptionsResponseSerializer, AdminVerifyRequestSerializer, AdminVerifyResponseSerializer


def admin_login_view(request):
    """Custom admin login view with 2FA support"""

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None and user.is_staff:
            # Check if admin 2FA is required
            if settings.ADMIN_2FA_REQUIRED:
                # Check what 2FA methods are available without creating them
                available_methods = get_available_2fa_methods(user)
                has_2fa_enabled = any(available_methods.values())

                if not has_2fa_enabled:
                    # First time login - create session and redirect to 2FA setup
                    session_id = create_authentication_session(user, request)
                    if session_id:
                        request.session['admin_2fa_session_id'] = session_id
                        return redirect('admin_2fa_setup')
                    else:
                        messages.error(request, 'Failed to create authentication session.')
                        return redirect('admin_login')
                else:
                    # 2FA is enabled - create session and redirect to verification
                    session_id = create_authentication_session(user, request)
                    if session_id:
                        request.session['admin_2fa_session_id'] = session_id
                        return redirect('admin_2fa_verify')
                    else:
                        messages.error(request, 'Failed to create authentication session.')
                        return redirect('admin_login')
            else:
                # 2FA not required for admins - proceed with normal login
                login(request, user)
                return redirect('admin:index')
        else:
            messages.error(request, 'Invalid credentials or insufficient permissions.')

    # Use Django's built-in admin login view for the template
    from django.contrib.admin import site as admin_site

    return admin_site.login(request)


def admin_2fa_setup_view(request):
    """Admin 2FA setup view"""
    # Get user from session since they're not fully authenticated yet
    session_id = request.session.get('admin_2fa_session_id')
    session, error = validate_session_data(session_id)
    if not session:
        return redirect('admin_login')

    user = session.user

    # Clean up any partial 2FA setup to ensure clean state
    if not has_totp_enabled(user) and has_passkey_enabled(user):
        # Clear passkey credentials if no TOTP is set up
        user.passkey_credentials.all().delete()

    if request.method == 'POST':
        setup_type = request.POST.get('setup_type')

        if setup_type == 'totp':
            # Generate TOTP secret and QR code
            totp_secret = generate_totp_secret()
            qr_code_b64 = generate_totp_qr_code(totp_secret, user)

            # Store the secret in session for verification (not in database yet)
            request.session['pending_totp_secret'] = totp_secret

            return render(
                request,
                '2fa_setup_totp.html',
                {'qr_code': qr_code_b64, 'secret': totp_secret},
            )

        elif setup_type == 'passkey':
            # Redirect to passkey setup
            return redirect('admin_2fa_setup_passkey')

    return render(request, '2fa_setup.html')


def admin_2fa_verify_view(request):
    """Admin 2FA verification view"""
    session_id = request.session.get('admin_2fa_session_id')
    session, error = validate_session_data(session_id)
    if not session:
        messages.error(request, 'Invalid or expired session.')
        return redirect('admin_login')

    user = session.user

    # Check if user has 2FA enabled
    if not is_2fa_enabled(user):
        # 2FA is not enabled, redirect to set up
        return redirect('admin_2fa_setup')

    # Get available verification methods
    available_methods = []
    if has_totp_enabled(user):
        available_methods.append('totp')
    if has_passkey_enabled(user):
        available_methods.append('passkey')
    # Backup codes are always available if 2FA is enabled
    available_methods.append('backup')

    # If no methods are available but 2FA is enabled, redirect to set up
    if len(available_methods) == 0:
        return redirect('admin_2fa_setup')

    if request.method == 'POST':
        totp_token = request.POST.get('totp_token')
        passkey_response = request.POST.get('passkey_response')
        backup_code = request.POST.get('backup_code')

        # Verify 2FA method
        if totp_token and has_totp_enabled(user):
            if verify_totp_login(user, totp_token):
                session.totp_verified = True
                session.save()
                login(request, user)
                del request.session['admin_2fa_session_id']
                return redirect('admin:index')

        elif passkey_response and has_passkey_enabled(user):
            if verify_passkey(user, json.loads(passkey_response), session_id):
                session.passkey_verified = True
                session.save()
                login(request, user)
                del request.session['admin_2fa_session_id']
                return redirect('admin:index')

        elif backup_code:
            if verify_backup_code(user, backup_code, get_client_ip(request), request.META.get('HTTP_USER_AGENT', '')):
                session.totp_verified = True
                session.save()
                login(request, user)
                del request.session['admin_2fa_session_id']
                return redirect('admin:index')

        messages.error(request, 'Invalid 2FA token.')

    return render(request, '2fa_verify.html', {'available_methods': available_methods, 'user': user})


def admin_2fa_setup_passkey_view(request):
    """Admin passkey setup view"""
    # Get user from session since they're not fully authenticated yet
    session_id = request.session.get('admin_2fa_session_id')

    if not session_id:
        return redirect('admin_login')

    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
        user = session.user
    except LoginSession.DoesNotExist:
        return redirect('admin_login')
    except Exception:
        # Log the error for debugging
        return redirect('admin_login')

    if request.method == 'POST':
        # Handle passkey setup
        passkey_response = request.POST.get('passkey_response')

        if passkey_response:
            try:
                # Get the session for challenge verification
                session = LoginSession.objects.get(session_id=session_id)

                # Use modern verify_registration_response API
                from webauthn import verify_registration_response

                # Parse the passkey response as JSON
                passkey_response_dict = json.loads(passkey_response)

                # Convert stored base64 challenge back to bytes
                import base64

                expected_challenge = base64.b64decode(session.challenge)

                # Verify the passkey registration response
                verification = verify_registration_response(
                    credential=passkey_response_dict,  # parsed JSON from frontend
                    expected_challenge=expected_challenge,  # converted back to bytes
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                )

                # Only save the credential after successful verification
                from .models import PasskeyCredential

                # Convert public key to base64 for storage
                public_key_base64 = base64.b64encode(verification.credential_public_key).decode('utf-8')

                # Create the passkey credential
                PasskeyCredential.objects.create(
                    user=user,
                    credential_id=verification.credential_id,
                    public_key=public_key_base64,  # Store as base64 string
                    sign_count=verification.sign_count,
                    rp_id=settings.WEBAUTHN_RP_ID,
                    user_handle=str(user.id),
                )

                # Generate backup codes
                backup_codes_obj = get_or_create_backup_codes(user)
                backup_codes_obj.codes = generate_backup_codes()
                backup_codes_obj.save()

                messages.success(request, 'Passkey setup completed successfully!')
                # Redirect to backup codes page instead of admin index
                return redirect('admin_2fa_backup_codes')

            except json.JSONDecodeError:
                messages.error(request, 'Invalid passkey response format.')
            except Exception as e:
                messages.error(request, f'Passkey setup failed: {str(e)}')
                # Log the error for debugging
                import logging

                logger = logging.getLogger(__name__)
                logger.error(f'Passkey setup failed for user {user.username}: {str(e)}')

    # Generate passkey options using modern webauthn API
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    from webauthn import generate_registration_options

    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_name=user.username,
        user_id=str(user.id).encode(),
        user_display_name=user.get_full_name() or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    # Store challenge in session (convert bytes to base64 for storage)
    new_session_id = str(uuid.uuid4())
    import base64

    challenge_base64 = base64.b64encode(options.challenge).decode('utf-8')
    LoginSession.objects.create(
        user=user,
        session_id=new_session_id,
        expires_at=timezone.now() + timezone.timedelta(minutes=settings.TWOFA_SESSION_TIMEOUT),
        challenge=challenge_base64,  # Store as base64 string
        ip_address=get_client_ip(request),
        user_agent=request.META.get('HTTP_USER_AGENT', ''),
    )

    # Update the Django session with the new session ID
    try:
        request.session['admin_2fa_session_id'] = new_session_id
        request.session.modified = True
        request.session.save()
    except Exception as e:
        print(f"Error saving session: {e}")
        # Continue anyway, the session might still work

    # Custom serialization for WebAuthn options
    def serialize_webauthn_options(options, visited=None):
        """Serialize WebAuthn options to JSON-compatible dict with camelCase keys"""
        if visited is None:
            visited = set()

        # Prevent circular references
        obj_id = id(options)
        if obj_id in visited:
            return str(options)  # Return string representation for circular refs
        visited.add(obj_id)

        # Field name mapping from snake_case to camelCase
        field_mapping = {
            'pub_key_cred_params': 'pubKeyCredParams',
            'authenticator_selection': 'authenticatorSelection',
            'user_verification': 'userVerification',
            'resident_key': 'residentKey',
            'attestation_conveyance': 'attestationConveyance',
            'exclude_credentials': 'excludeCredentials',
            'supported_pub_key_algs': 'supportedPubKeyAlgs',
            'display_name': 'displayName',  # User entity field
        }

        result = {}
        for key, value in options.__dict__.items():
            try:
                # Convert snake_case to camelCase
                camel_key = field_mapping.get(key, key)

                if hasattr(value, '__dict__') and not isinstance(value, (str, int, float, bool)):
                    # Handle nested objects
                    result[camel_key] = serialize_webauthn_options(value, visited)
                elif isinstance(value, bytes):
                    # Convert bytes to base64
                    import base64

                    result[camel_key] = base64.b64encode(value).decode('utf-8')
                elif isinstance(value, list):
                    # Handle lists
                    result[camel_key] = []
                    for item in value:
                        if hasattr(item, '__dict__') and not isinstance(item, (str, int, float, bool)):
                            result[camel_key].append(serialize_webauthn_options(item, visited))
                        else:
                            result[camel_key].append(item)
                else:
                    result[camel_key] = value
            except Exception:
                # If we can't serialize a value, convert it to string
                result[camel_key] = str(value)

        visited.remove(obj_id)
        return result

    return render(
        request,
        '2fa_setup_passkey.html',
        {'options': json.dumps(serialize_webauthn_options(options)), 'session_id': new_session_id},
    )


def admin_2fa_backup_codes_view(request):
    """Admin backup codes display view"""
    # Get user from session since they're not fully authenticated yet
    session_id = request.session.get('admin_2fa_session_id')
    if not session_id:
        return redirect('admin_login')

    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
        user = session.user
    except LoginSession.DoesNotExist:
        return redirect('admin_login')

    # Get the user's backup codes
    try:
        from .views import get_or_create_backup_codes

        backup_codes_obj = get_or_create_backup_codes(user)
        backup_codes = backup_codes_obj.codes
    except Exception:
        return redirect('admin_2fa_setup')

    if request.method == 'POST':
        # User has acknowledged the backup codes
        return redirect('admin:index')

    return render(request, '2fa_backup_codes.html', {'backup_codes': backup_codes, 'user': user})


def admin_2fa_verify_totp_setup(request):
    """Admin TOTP setup verification"""
    # Get user from session
    session_id = request.session.get('admin_2fa_session_id')
    session, error = validate_session_data(session_id)
    if not session:
        return redirect('admin_login')

    user = session.user

    if request.method == 'POST':
        totp_token = request.POST.get('totp_token')
        secret = request.session.get('pending_totp_secret')

        if secret and totp_token:
            # Verify the TOTP token
            if verify_totp_token_setup(secret, totp_token):
                # Complete TOTP setup
                if setup_totp_complete(user, secret):
                    # Clear the pending secret from session
                    if 'pending_totp_secret' in request.session:
                        del request.session['pending_totp_secret']

                    messages.success(request, 'TOTP setup completed successfully!')
                    return redirect('admin_2fa_backup_codes')
                else:
                    messages.error(request, 'Failed to complete TOTP setup.')
            else:
                messages.error(request, 'Invalid TOTP token. Please try again.')
        else:
            messages.error(request, 'Missing required fields or no pending TOTP setup.')

    return redirect('admin_2fa_setup')


@extend_schema(
    summary="Get admin 2FA authentication options",
    description="Generate passkey authentication options for admin login",
    tags=["Admin 2FA"],
    request=None,
    responses={
        200: AdminAuthOptionsResponseSerializer,
        400: OpenApiResponse(description="No active session"),
        500: OpenApiResponse(description="Failed to generate authentication options"),
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_2fa_auth_options(request):
    """API endpoint for admin passkey authentication options"""
    session_id = request.session.get('admin_2fa_session_id')
    session, error = validate_session_data(session_id)
    if not session:
        return Response({'error': 'No active session'}, status=status.HTTP_400_BAD_REQUEST)

    # Generate authentication options
    options = custom_generate_authentication_options()
    if not options:
        return Response(
            {'error': 'Failed to generate authentication options'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # Store challenge in session
    challenge_base64 = base64.b64encode(options.challenge).decode('utf-8')
    session.challenge = challenge_base64
    session.save()

    return Response({'challenge': challenge_base64, 'rp_id': options.rp_id, 'timeout': options.timeout})


@extend_schema(
    summary="Verify admin 2FA",
    description="Verify admin 2FA using TOTP, passkey, or backup code",
    tags=["Admin 2FA"],
    request=AdminVerifyRequestSerializer,
    responses={
        200: AdminVerifyResponseSerializer,
        400: OpenApiResponse(description="Invalid or expired session"),
        401: OpenApiResponse(description="Invalid 2FA token"),
    },
)
@api_view(['POST'])
@permission_classes([AllowAny])
def admin_2fa_verify_api(request):
    """API endpoint for admin 2FA verification"""
    session_id = request.data.get('session_id')
    totp_token = request.data.get('totp_token')
    passkey_response = request.data.get('passkey_response')
    backup_code = request.data.get('backup_code')

    try:
        session = LoginSession.objects.get(session_id=session_id, expires_at__gt=timezone.now())
    except LoginSession.DoesNotExist:
        return Response({'error': 'Invalid or expired session'}, status=status.HTTP_400_BAD_REQUEST)

    # Verify 2FA method
    if totp_token and has_totp_enabled(session.user):
        if verify_totp_login(session.user, totp_token):
            session.totp_verified = True
            session.save()
            return Response({'success': True})

    elif passkey_response and session.user.passkey_credentials.exists():
        if verify_passkey(session.user, passkey_response, session_id):
            session.passkey_verified = True
            session.save()
            return Response({'success': True})

    elif backup_code:
        if verify_backup_code(
            session.user, backup_code, get_client_ip(request), request.META.get('HTTP_USER_AGENT', '')
        ):
            session.totp_verified = True
            session.save()
            return Response({'success': True})

    return Response({'error': 'Invalid 2FA token'}, status=status.HTTP_401_UNAUTHORIZED)


# Current User Setup Views (for admin actions)
def admin_current_user_totp_setup(request):
    """TOTP setup view for current admin user"""
    if not request.user.is_authenticated or not request.user.is_staff:
        # Use appropriate login URL based on 2FA setting
        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            return redirect('admin_login')
        else:
            return redirect('admin:login')

    user = request.user
    get_or_create_2fa(user)

    if request.method == 'POST':
        # Handle TOTP verification
        totp_code = request.POST.get('totp_code')
        secret = request.session.get('pending_current_user_totp_secret')

        if totp_code and secret:
            # Verify the TOTP token
            if verify_totp_token_setup(secret, totp_code):
                # Complete TOTP setup
                if setup_totp_complete(user, secret):
                    # Clear the pending secret from session
                    if 'pending_current_user_totp_secret' in request.session:
                        del request.session['pending_current_user_totp_secret']

                    messages.success(request, 'TOTP setup completed successfully!')
                    return redirect('admin_current_user_backup_codes')
                else:
                    messages.error(request, 'Failed to complete TOTP setup.')
            else:
                messages.error(request, 'Invalid TOTP code. Please try again.')
        else:
            messages.error(request, 'Missing required fields or no pending TOTP setup.')

    # Generate TOTP secret and QR code
    totp_secret = generate_totp_secret()
    qr_code_b64 = generate_totp_qr_code(totp_secret, user)

    # Store the secret in session for verification (not in database yet)
    request.session['pending_current_user_totp_secret'] = totp_secret

    return render(
        request,
        '2fa_setup_totp.html',
        {'qr_code': qr_code_b64, 'secret': totp_secret, 'user': user, 'is_current_user': True},
    )


def admin_current_user_passkey_setup(request):
    """Passkey setup view for current admin user"""
    if not request.user.is_authenticated or not request.user.is_staff:
        # Use appropriate login URL based on 2FA setting
        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            return redirect('admin_login')
        else:
            return redirect('admin:login')

    user = request.user

    if request.method == 'POST':
        # Handle passkey setup
        passkey_response = request.POST.get('passkey_response')

        if passkey_response:
            try:
                # Use modern verify_registration_response API
                from webauthn import verify_registration_response

                # Parse the passkey response as JSON
                passkey_response_dict = json.loads(passkey_response)

                # Convert stored base64 challenge back to bytes
                challenge_base64 = request.session.get('current_user_passkey_challenge')
                if not challenge_base64:
                    messages.error(request, 'Challenge not found. Please try again.')
                    return redirect('admin_current_user_passkey_setup')

                expected_challenge = base64.b64decode(challenge_base64)

                verification = verify_registration_response(
                    credential=passkey_response_dict,
                    expected_challenge=expected_challenge,
                    expected_rp_id=settings.WEBAUTHN_RP_ID,
                    expected_origin=settings.WEBAUTHN_ORIGIN,
                )

                # Save the credential
                from .models import PasskeyCredential

                public_key_base64 = base64.b64encode(verification.credential_public_key).decode('utf-8')

                PasskeyCredential.objects.create(
                    user=user,
                    credential_id=verification.credential_id,
                    public_key=public_key_base64,
                    sign_count=verification.sign_count,
                    rp_id=settings.WEBAUTHN_RP_ID,
                    user_handle=str(user.id),
                )

                # Generate backup codes
                backup_codes_obj = get_or_create_backup_codes(user)
                backup_codes_obj.codes = generate_backup_codes()
                backup_codes_obj.save()

                messages.success(request, 'Passkey setup completed successfully!')
                return redirect('admin_current_user_backup_codes')

            except json.JSONDecodeError:
                messages.error(request, 'Invalid passkey response format.')
            except Exception as e:
                messages.error(request, f'Passkey setup failed: {str(e)}')
                # Log the error for debugging
                import logging

                logger = logging.getLogger(__name__)
                logger.error(f'Current user passkey setup failed for user {user.username}: {str(e)}')

    # Generate passkey options
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )
    from webauthn import generate_registration_options

    user_id_bytes = str(user.id).encode('utf-8')

    options = generate_registration_options(
        rp_id=settings.WEBAUTHN_RP_ID,
        rp_name=settings.WEBAUTHN_RP_NAME,
        user_name=user.username,
        user_id=user_id_bytes,
        user_display_name=user.get_full_name() or user.username,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.PREFERRED, user_verification=UserVerificationRequirement.REQUIRED
        ),
        attestation=AttestationConveyancePreference.NONE,
    )

    # Store challenge in session
    challenge_base64 = base64.b64encode(options.challenge).decode('utf-8')
    request.session['current_user_passkey_challenge'] = challenge_base64

    # Serialize options for JavaScript
    def serialize_webauthn_options(options, visited=None):
        if visited is None:
            visited = set()

        result = {}
        for key, value in options.__dict__.items():
            if key in visited:
                continue
            visited.add(key)

            camel_key = ''.join(word.capitalize() if i > 0 else word for i, word in enumerate(key.split('_')))

            if key == 'challenge':
                result[camel_key] = base64.b64encode(value).decode('utf-8')
            elif key == 'user':
                result[camel_key] = {
                    'id': base64.b64encode(value.id).decode('utf-8'),
                    'name': value.name,
                    'displayName': value.display_name,
                }
            elif key == 'rp':
                result[camel_key] = {'name': value.name, 'id': value.id}
            elif key == 'pub_key_cred_params':
                result[camel_key] = [{'alg': param.alg, 'type': param.type} for param in value]
            elif key == 'authenticator_selection':
                result[camel_key] = {
                    'residentKey': value.resident_key.value,
                    'userVerification': value.user_verification.value,
                }
            elif key == 'attestation':
                result[camel_key] = value.value
            elif hasattr(value, 'value'):  # Handle enum-like objects
                result[camel_key] = value.value
            else:
                result[camel_key] = value

        return result

    serialized_options = serialize_webauthn_options(options)

    return render(
        request,
        '2fa_setup_passkey.html',
        {'options': json.dumps(serialized_options), 'user': user, 'is_current_user': True},
    )


def admin_current_user_backup_codes(request):
    """Backup codes view for current admin user"""
    if not request.user.is_authenticated or not request.user.is_staff:
        # Use appropriate login URL based on 2FA setting
        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            return redirect('admin_login')
        else:
            return redirect('admin:login')

    user = request.user
    get_or_create_2fa(user)

    if request.method == 'POST':
        # User has acknowledged the backup codes - redirect to PasskeyCredential admin
        messages.success(request, '2FA setup completed successfully!')
        return redirect('admin:lokdown_passkeycredential_changelist')

    if not has_backup_codes(user):
        messages.error(request, 'No backup codes found. Please complete 2FA setup first.')
        return redirect('admin:lokdown_usertwofactorauth_changelist')

    backup_codes_obj = get_or_create_backup_codes(user)
    backup_codes = backup_codes_obj.codes

    return render(
        request, '2fa_backup_codes.html', {'backup_codes': backup_codes, 'user': user, 'is_current_user': True}
    )


def admin_backup_codes_display(request):
    """Admin backup codes display view for regenerated codes"""
    if not request.user.is_authenticated or not request.user.is_staff:
        # Use appropriate login URL based on 2FA setting
        if getattr(settings, 'ADMIN_2FA_REQUIRED', False):
            return redirect('admin_login')
        else:
            return redirect('admin:login')

    # Get regenerated codes from session or request
    regenerated_codes = request.session.get('regenerated_backup_codes', {})

    if not regenerated_codes:
        messages.error(request, 'No regenerated backup codes found.')
        return redirect('admin:lokdown_backupcodes_changelist')

    codes_count = len(regenerated_codes)

    if request.method == 'POST':
        download_format = request.POST.get('download_format')

        if download_format in ['txt', 'csv']:
            from django.http import HttpResponse

            if download_format == 'txt':
                content = "Backup Codes\n\n"
                for username, codes in regenerated_codes.items():
                    content += f"User: {username}\n"
                    content += "Codes:\n"
                    for code in codes:
                        content += f"  {code}\n"
                    content += "\n"

                response = HttpResponse(content, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="backup_codes.txt"'

            else:  # csv
                import csv
                from io import StringIO

                output = StringIO()
                writer = csv.writer(output)
                writer.writerow(['Username', 'Backup Code'])

                for username, codes in regenerated_codes.items():
                    for code in codes:
                        writer.writerow([username, code])

                response = HttpResponse(output.getvalue(), content_type='text/csv')
                response['Content-Disposition'] = 'attachment; filename="backup_codes.csv"'

            # Clear the session data after download
            if 'regenerated_backup_codes' in request.session:
                del request.session['regenerated_backup_codes']

            return response

    return render(
        request,
        'templates/backup_codes_display.html',
        {
            'codes_count': codes_count,
            'regenerated_codes': regenerated_codes,
        },
    )
