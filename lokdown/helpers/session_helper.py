"""
Session helpers — re-exports from auth_flow_helper for backwards compatibility.
"""

from lokdown.helpers.auth_flow_helper import (
    create_authentication_session,
    validate_session_data,
    verify_second_factor,
)

get_session = verify_second_factor

__all__ = [
    "create_authentication_session",
    "validate_session_data",
    "verify_second_factor",
    "get_session",
]
