from fastapi import HTTPException, Cookie, status
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = "secret-key-ohya"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIER_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7 

def create_access_token(data: dict, expires_delta : Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIER_MINUTES))
    to_encode.update({"exp" : expire})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encode_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp" : expire, "type" : "refresh"})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encode_jwt

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = ALGORITHM)
        account = payload.get("sub")
        return account
    except JWTError:
        return None
    
def get_user(jwt: Optional[str] = Cookie(None)):
    if jwt is None:
        raise HTTPException(status_code=401)
    account = verify_token(jwt)
    if account is None:
        raise HTTPException(status_code=401)
    return account