from fastapi import FastAPI,Depends, HTTPException, status, Response, Cookie, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from pydantic import BaseModel
import bcrypt
import sqlite3
import json

class LoginRequest(BaseModel):
    account: str
    password: str

    def all(self):
        return bool(self.account and self.password)

class Username(BaseModel):
    name: str

class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, dict] = {}

    async def connect(self, websocket: WebSocket, account: str, name: str):
        await websocket.accept()
        self.active_connections[account] = {
            "ws" : websocket,
            "name" : name
        }
    
    def disconnect(self, websocket: WebSocket):
        for account, data in list(self.active_connections.items()):
            if data["ws"] == websocket:
                del self.active_connections[account]

    async def broadcast(self,account: str, message: str):
        sender = self.active_connections[account]["name"]
        for ws in self.active_connections.values():
            await ws["ws"].send_text(f"{sender}: {message}")

    async def send_personal(self, to_account: str, sender_account: str, message: str):
        ws = self.active_connections.get(to_account)
        if ws:
            sender_name = self.active_connections[sender_account]["name"]
            await ws["ws"].send_text(f"(私訊){sender_name}: {message}")


manager = ConnectionManager()

first_conn = sqlite3.connect("user.db")
first_cur = first_conn.cursor()
# 建資料庫
first_cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT UNIQUE,
    password TEXT,
    name TEXT
)                  
""")
# 建對話庫
first_cur.execute("""
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
        return account
    except JWTError:
        return None
    
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

            cur.execute("INSERT INTO users (account, password, name) VALUES (?, ?, ?)",
                        (req.account, hash_password, req.account))
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

@app.post("/user/username")
def update_name(req:Username, account: str = Depends(get_user)):
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET name = ? WHERE account = ?", (req.name, account))
        conn.commit()
    
    if account in manager.active_connections:
        manager.active_connections[account]["name"] = req.name

    return {"success": True}

@app.get("/user/username")
def get_name(account: str = Depends(get_user)):
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE account = ?", (account, ))
        row = cur.fetchone()

    return {"name": row[0]}

@app.websocket("/ws/chat")
async def chat(websocket: WebSocket, token: str = Query(...)):    
    account = verify_token(token)
    if not account:
        await websocket.close(code = 1008)
        return
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE account = ?", (account,))
        row = cur.fetchone()
    name = row[0] if row else account
    await manager.connect(websocket, account, name)

    try:
        while True:
            msg = json.loads(await websocket.receive_text())
            to = msg.get("to")
            content = msg.get("message")

            if to and to != "all":
                await manager.send_personal(to, account, content)
            else:
                await manager.broadcast(account, content)

            with sqlite3.connect("user.db") as conn:
                cur = conn.cursor()
                cur.execute("INSERT INTO messages (account, content) VALUES (?, ?)", (account, content))
                conn.commit()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

@app.get("/messages")
def get_msg(limit: int = 50):  # 取limit條訊息
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT m.account, u.name, m.content, m.created_at
            FROM messages m
            JOIN users u ON m.account = u.account
            ORDER BY m.id DESC
            LIMIT ?
        """, (limit,))
        row = cur.fetchall()

    row.reverse()
    return [{"account": r[0], "name": r[1], "content": r[2], "created_at": r[3]} for r in row]

@app.get("/home", response_class=HTMLResponse)
def home_page():
    return FileResponse("static/home.html")