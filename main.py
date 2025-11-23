from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import sqlite3

class LoginRequest(BaseModel):
    username: str
    gmail: str
    password: str

    def all(self):
        if self.username != "" and self.gmail != "" and self.password != "":
            return True
        return False

# 建資料庫
first_conn = sqlite3.connect("user.db")
first_cur = first_conn.cursor()
first_cur.execute("""
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    gmail TEXT UNIQUE,
    password TEXT
)                  
""")
first_conn.commit()
first_conn.close()

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/", response_class=HTMLResponse)
def root():
    return FileResponse("static/login.html")

@app.post("/register")
def register_userdata(req: LoginRequest):
    conn = sqlite3.connect("user.db")
    cur = conn.cursor()

    if req.all():
        cur.execute("INSERT INTO users (username, gmail, password) VALUES (?, ?, ?)",
                    (req.username, req.gmail, req.password))
        conn.commit()
        return {"success": True, "message": "註冊成功"}
    return {"success": False, "message": "資料不齊全，請輸入完整"}

@app.post("/login")
def login_userdata(req: LoginRequest):
    conn = sqlite3.connect("user.db")
    cur = conn.cursor()

    cur.execute("SELECT password FROM users WHERE gmail = ?", (req.gmail,))
    row = cur.fetchone()

    if row is None:
        return {"success": False, "message": "使用者不存在，請先註冊"}
    if row[0] == req.password:
        return {"success": True, "message": "登入成功"}
    
    return {"success": False, "message": "密碼錯誤"}

@app.get("/home", response_class=HTMLResponse)
def home_page():
    return "Success!!!"