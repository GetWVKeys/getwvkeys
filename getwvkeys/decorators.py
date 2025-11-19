from functools import update_wrapper, wraps

from flask import jsonify, request
from flask_login import current_user, login_user
from werkzeug.exceptions import BadRequest, Forbidden, Unauthorized

from getwvkeys import config
from getwvkeys.models.Shared import db
from getwvkeys.user import FlaskUser


def authentication_required(exempt_methods=[], flags_required: int = None, ignore_suspended: bool = False):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if request.method in exempt_methods:
                return func(*args, **kwargs)
            if config.LOGIN_DISABLED:
                return func(*args, **kwargs)

            # handle api keys
            if not current_user.is_authenticated:
                # check if they passed in an api key
                api_key = request.headers.get("X-API-Key") or request.headers.get("Authorization")
                if not api_key:
                    raise Unauthorized("API Key Required")

                # check if the key is a bot
                if FlaskUser.is_api_key_bot(api_key):
                    return func(*args, **kwargs)

                # check if the key is a valid user key
                user = FlaskUser.get_user_by_api_key(db, api_key)

                if not user:
                    raise Forbidden("Invalid API Key")

                login_user(user, remember=False)

            # check if the user is enabled
            current_user.check_status(ignore_suspended)

            # check if the user has the required flags
            if flags_required and not current_user.flags.has(flags_required):
                raise Forbidden("Missing Access")

            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


# require and validate cdm id for remote cdm operations
def remotecdm_validate_cdmid():
    def decorator(func):
        @wraps(func)
        def wrapped_function(cdm_id, *args, **kwargs):
            cdm_id = cdm_id.lower()
            if cdm_id not in ["widevine", "playready"]:
                return (
                    jsonify(
                        {
                            "status": 400,
                            "message": "Invalid CDM ID.",
                        }
                    ),
                    400,
                )
            return func(cdm_id, *args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


# require and validate api key for remote cdm operations
def remotecdm_authentication_required(exempt_methods=[]):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            if request.method in exempt_methods:
                return func(*args, **kwargs)

            # handle api keys
            if not current_user.is_authenticated:
                # check if they passed in an api key
                api_key = request.headers.get("X-Secret-Key")
                if not api_key:
                    raise Unauthorized("API Key Required")

                # check if the key is a valid user key
                user = FlaskUser.get_user_by_api_key(db, api_key)

                if not user:
                    raise Forbidden("Invalid API Key")

                login_user(user, remember=False)

            # check if the user is enabled
            current_user.check_status()

            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


# optional auth, if api key specified, get the user
def optional_auth():
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            api_key = request.headers.get("X-API-Key")
            if api_key:
                user = FlaskUser.get_user_by_api_key(db, api_key)
                if user:
                    login_user(user, remember=False)
            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


# only allow specified cdm ids to use an operation
def remotecdm_require_cdmids(cdm_ids=[]):
    def decorator(func):
        @wraps(func)
        def wrapped_function(cdm_id, *args, **kwargs):
            if cdm_id not in cdm_ids:
                return (
                    jsonify(
                        {
                            "status": 400,
                            "message": f"Unsupported operation for specified CDM id",
                        }
                    ),
                    400,
                )
            return func(cdm_id, *args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator


# decorator that takes a list of required body keys and validates they exist
def ensure_body_keys(required_keys=[]):
    def decorator(func):
        @wraps(func)
        def wrapped_function(*args, **kwargs):
            event_data = request.get_json()
            if not event_data:
                raise BadRequest("Missing Body")
            for key in required_keys:
                if key not in event_data:
                    raise BadRequest(f"Missing Field: {key}")
            return func(*args, **kwargs)

        return update_wrapper(wrapped_function, func)

    return decorator
