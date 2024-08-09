import jwt
import datetime
import secrets

# Generate a secure SECRET_KEY
SECRET_KEY = secrets.token_hex(32)

def generate_auth_token(user):
    payload = {
        'user_id': user.id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def verify_auth_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
