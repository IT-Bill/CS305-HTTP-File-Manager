import uuid
import time

sessions = {}

def generate_session_id(user, session_timeout=10):
    """Generate a unique session ID for a given username."""
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "user": user,
        "expires": time.time() + session_timeout
    }

    return session_id

def validate_session_id(session_id):
    """Check if the session ID is valid and has not expired."""
    session_info = sessions.get(session_id, None)
    if session_info and session_info['expires'] > time.time():
        return session_info['user']
    return None

    