from fastapi import FastAPI, Depends, HTTPException, status, Response, Cookie, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from routers import friends
import bcrypt
import sqlite3
import json
import sys
import os
import uuid

# --- 這裡匯入我們拆分出去的模組 ---
# 從 dependencies.py 導入 JWT 相關函式 請確保同一層目錄下有 dependencies.py
from dependencies import create_access_token, create_refresh_token, verify_token, get_user
# 從 routers 資料夾導入任務和懸賞系統 確保有 routers 資料夾，裡面有 tasks.py
from routers import bounty, memo

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# --- 聊天室區塊 ---
# 定義 Request 模型 (這些只在 main 用到，所以留著)
# 處理登入和註冊請求的資料模型
class LoginRequest(BaseModel):
    account: str
    password: str

    def all(self):
        return bool(self.account and self.password)

class Username(BaseModel):
    name: str

# websocket 連線管理器 (這是聊天室核心，保留在 main)
class ConnectionManager:
    def __init__(self):
        # 儲存所有活躍的 websocket 連線
        self.active_connections: dict[str, dict] = {}

    # 建立連線、儲存用戶資訊
    async def connect(self, websocket: WebSocket, account: str, name: str):
        await websocket.accept()    # 接受 websocket 連線請求
        self.active_connections[account] = {
            "ws" : websocket,
            "name" : name
        }

    # 移除斷線用戶
    def disconnect(self, websocket: WebSocket):
        for account, data in list(self.active_connections.items()):
            if data["ws"] == websocket:
                del self.active_connections[account]

    # 廣播消息給所有用戶
    async def broadcast(self, account: str, message: str):
        sender = self.active_connections[account]["name"]   # 取得發送者名稱
        for ws in self.active_connections.values():
            await ws["ws"].send_text(f"{sender}: {message}")    # 發送訊息

    # 私訊功能
    async def send_personal(self, to_account: str, sender_account: str, message: str):
        ws = self.active_connections.get(to_account)    # 取得接收者的連線資訊
        if ws:
            sender_name = self.active_connections[sender_account]["name"]   # 取得發送者名稱
            # 發送 JSON 格式的私訊，包含 type 標記
            await ws["ws"].send_text(json.dumps({
                "type": "private",
                "sender": sender_name,
                "sender_account": sender_account,
                "content": message
            }))

manager = ConnectionManager()

# --- 初始化資料庫 ---
first_conn = sqlite3.connect("user.db")
first_cur = first_conn.cursor()

# 1. Users 表 登入系統
first_cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT UNIQUE,
    password TEXT,
    name TEXT
)                  
""")
# 2. Messages 表 聊天室
first_cur.execute("""
CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT,
    content TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
# 3. Bounty 表 (懸賞任務:大家都可以接取)
first_cur.execute("""
CREATE TABLE IF NOT EXISTS bounty(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,                 --發任務的人
    taker TEXT,                 --接任務的人
    title TEXT,
    description TEXT,
    reward INTEGER,             --報酬
    status TEXT DEFAULT 'open', --open / take / finish / cancel
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
# 4. Friends 表 (好友系統)
first_cur.execute("""
CREATE TABLE IF NOT EXISTS friends(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_account TEXT,
    friend_account TEXT,
    status TEXT DEFAULT 'pending', -- pending / accepted / blocked
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_account, friend_account)
)
""")
# 5. Private Messages 表 (私訊系統)
first_cur.execute("""
CREATE TABLE IF NOT EXISTS private_messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_account TEXT,
    receiver_account TEXT,
    content TEXT,
    is_read BOOLEAN DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
# 6.  memos 表
first_cur.execute("""
CREATE TABLE IF NOT EXISTS memos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    deadline TEXT,                   
    is_completed BOOLEAN DEFAULT 0,  
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")
first_conn.commit()
first_conn.close()


# --- FastAPI App 初始化 ---
app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

# **關鍵步驟：掛載任務系統的 Router**
app.include_router(bounty.router)
app.include_router(friends.router)
app.include_router(memo.router)

# --- 原本的路由與邏輯 ---
# 登入畫面
@app.get("/", response_class=HTMLResponse)
def root():
    return FileResponse("static/login.html")

# 註冊功能
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

# 登入功能
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
        
        # 這裡呼叫的是 dependencies 匯入的函式
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
def refresh_token_endpoint(refresh: str | None = Cookie(None)): # 為了避免命名衝突，改個函式名
    if refresh is None:
        raise HTTPException(status_code=401, detail="Missing refresh token")
    
    # 這裡的邏輯我稍微簡化，因為 verify_token 已經在 dependencies 裡了
    # 但為了原本的 refresh 邏輯，我們需要解碼判斷 type
    from dependencies import SECRET_KEY, ALGORITHM, jwt, JWTError # 局部引用，避免汙染全域
    
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

# 更新用戶名稱
@app.post("/user/username")
def update_name(req:Username, account: str = Depends(get_user)):
    with sqlite3.connect("user.db") as conn:    # 建立資料庫連線
        cur = conn.cursor()
        cur.execute("UPDATE users SET name = ? WHERE account = ?", (req.name, account)) # 更新用戶名稱
        conn.commit()
    
    # 如果用戶在聊天室中 更新連線管理器中的名稱
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

# websocket 聊天室端點
# websocket 聊天室端點 - 恢復簡單版本
@app.websocket("/ws/chat")
async def chat(websocket: WebSocket, token: str = Query(...)):    
    # 這裡使用 dependencies 裡的 verify_token
    account = verify_token(token)   # 驗證 JWT token
    if not account:
        await websocket.close(code = 1008)
        return
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT name FROM users WHERE account = ?", (account,))
        row = cur.fetchone()

    name = row[0] if row else account
    await manager.connect(websocket, account, name) # 建立 WebSocket 連線

    try:
        while True:
            msg = json.loads(await websocket.receive_text())
            to = msg.get("to")
            content = msg.get("message")

            # 判斷是私訊還是廣播
            if to and to != "all":
                await manager.send_personal(to, account, content)
            else:
                await manager.broadcast(account, content)

            # 將訊息儲存到資料庫
            with sqlite3.connect("user.db") as conn:
                cur = conn.cursor()
                cur.execute("INSERT INTO messages (account, content) VALUES (?, ?)", (account, content))
                conn.commit()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

# 獲取歷史訊息
@app.get("/messages")
def get_msg(limit: int = 50):   # 限制上限50條
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

# 主頁面
@app.get("/home", response_class=HTMLResponse)
def home_page():
    return FileResponse("static/home.html")