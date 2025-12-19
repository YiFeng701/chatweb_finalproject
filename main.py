from fastapi import FastAPI
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
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

            cur.execute("INSERT INTO users (account, password) VALUES (?, ?)",
                        (req.account, req.password))
            conn.commit()
            return {"success": True, "message": "註冊成功，請登入"}
    except sqlite3.IntegrityError:
        return {"success": False, "message": "帳號已存在"}
    except Exception as e:
        return {"success": False, "message": f"註冊發生錯誤: {e}"}

@app.post("/login")
def login_userdata(req: LoginRequest):
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()

        cur.execute("SELECT password FROM users WHERE account = ?", (req.account,))
        row = cur.fetchone()

        if row is None:
            return {"success": False, "message": "使用者不存在，請先註冊"}
        if row[0] == req.password:
            return {"success": True, "message": "登入成功"}
        
        return {"success": False, "message": "密碼錯誤"}

@app.get("/home", response_class=HTMLResponse)
def home_page():
    return "Success!!!"