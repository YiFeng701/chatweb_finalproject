from fastapi import FastAPI,Depends, HTTPException, status, Response, Cookie
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
import bcrypt
import sqlite3

class LoginRequest(BaseModel):
    account: str
    password: str

    def all(self):
        return bool(self.account and self.password)

# 建資料庫
first_conn = sqlite3.connect("user.db")
first_cur = first_conn.cursor()
first_cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT UNIQUE,
    password TEXT
)                  
""")
first_conn.commit()
first_conn.close()

# 登入後的認證token
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

def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = ALGORITHM)
        account = payload.get("sub")
        if account is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return account
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    
def get_user(jwt: Optional[str] = Cookie(None)):
    if jwt is None:
        raise HTTPException(status_code=401)
    return verify_token(jwt)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp" : expire, "type" : "refresh"})
    encode_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encode_jwt

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def root():
    return FileResponse("static/login.html")

@app.post("/register")
def register_userdata(req: LoginRequest):
    if not req.all():
        return {"success": False, "message": "資料不齊全，請輸入完整"}

    try:
        with sqlite3.connect("user.db") as conn:
            cur = conn.cursor()
            hash_password = bcrypt.hashpw(
                req.password.encode("utf-8"),
                bcrypt.gensalt()
            )

            cur.execute("INSERT INTO users (account, password) VALUES (?, ?)",
                        (req.account, hash_password))
            conn.commit()
            return {"success": True, "message": "註冊成功，請登入"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "帳號已存在"}
    except Exception as e:
        return {"success": False, "message": f"註冊發生錯誤: {e}"}

@app.post("/login")
def login_userdata(req: LoginRequest, response: Response):
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()

        cur.execute("SELECT account, password FROM users WHERE account = ?", (req.account,))
        row = cur.fetchone()

        if row is None:
            return {"success": False, "message": "使用者不存在，請先註冊"}
        if not bcrypt.checkpw(
            req.password.encode("utf-8"),
            row[1]
        ):
            return {"success": False, "message": "密碼錯誤"}
        
        access_token = create_access_token({"sub" : row[0]})
        refresh_token = create_refresh_token({"sub" : row[0]})

        response.set_cookie(
            key = "jwt",
            value = access_token,
            httponly = True,
            samesite = "lax"
        )

        response.set_cookie(
            key = "refresh",
            value = refresh_token,
            httponly = True,
            samesite = "lax",
            max_age = 7 * 24 * 60 *60
        )

        
        return {
            "success": True, 
            "message": "登入成功",
            "access_token": access_token,
            "token_type": "bearer"
        }

@app.post("/refresh")
def refresh_token(refresh: Optional[str] = Cookie(None)):
    if refresh is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    
    try:
        payload = jwt.decode(refresh, SECRET_KEY, algorithms = ALGORITHM)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
        account = payload.get("sub")
        if account is None:
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    
    new_access_token = create_access_token({"sub": account})
    new_refresh_token = create_refresh_token({"sub": account})

    response = JSONResponse(content = {
        "success": True,
        "access_token": new_access_token
    })
    response.set_cookie(
        key = "jwt",
        value = new_access_token,
        httponly = True,
        samesite = "lax"
    )

    response.set_cookie(
        key = "refresh",
        value = new_refresh_token,
        httponly = True,
        samesite = "lax",
        max_age = 7 * 24 * 60 *60
    )

    return response

@app.get("/home", response_class=HTMLResponse)
def home_page(account: str = Depends(get_user)):
    return f"Welcome {account}"