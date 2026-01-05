from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
from dependencies import get_user
from typing import Optional

router = APIRouter(
    prefix="/bounty",
    tags=["懸賞任務"]
)

class Bounty(BaseModel):
    title: str
    description: Optional[str] = None
    reward: int

# 1. 發布任務
@router.post("/")
def create_bounty(bounty: Bounty, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    if bounty.reward < 0:
        raise HTTPException(status_code=400, detail="懸賞報酬需要大於等於0")
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO bounty(owner, title, description, reward) VALUES (?, ?, ?, ?)", 
                (account, bounty.title, bounty.description, bounty.reward))
        conn.commit()
    return {"success": True, "message": "懸賞任務已發布"}

# 2. 查看懸賞任務
@router.get("/open")
def list_bounties():
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row  # 可以轉成dict
        cur = conn.cursor()
        cur.execute("""
            SELECT b.id, b.title, b.description, b.reward,
                   u.name AS owner_name
            FROM bounty b
            JOIN users u ON b.owner = u.account
            WHERE b.status = 'open'
            ORDER BY b.id DESC
        """)
        rows = cur.fetchall()
    return [dict(r) for r in rows]


# 3. 接取任務
@router.post("/{id}/take")
def take_bounty(id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT status, owner FROM bounty WHERE id = ?", (id, ))
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="任務不存在")
        if row[0] != 'open':
            raise HTTPException(status_code=400, detail="任務已被接取")
        if row[1] == account:
            raise HTTPException(status_code=400, detail="不能接自己的任務")

        cur.execute("UPDATE bounty SET taker = ?, status = 'take' WHERE id = ?", (account, id))
        conn.commit()
    return {"success": True, "message": "任務接取成功"}

# 4. 完成任務
@router.post("/{id}/finish")
def finish_bounty(id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT owner, taker, status FROM bounty WHERE id = ?", (id, ))
        row = cur.fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="任務不存在")
        if row[0] != account:
            raise HTTPException(status_code=400, detail="只有發布者可以結束任務")
        if row[2] != 'take':
            raise HTTPException(status_code=400, detail="任務未被接取")

        cur.execute("UPDATE bounty SET status = 'finish' WHERE id = ?", (id, ))
        conn.commit()
    return {"success": True, "message": "任務完成"}

# 5-1. 我街的任務
@router.get("/my/taker")
def get_my_take_bounty(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT id, title, description, reward, owner
            FROM bounty
            WHERE taker = ?
            ORDER BY id DESC
        """, (account, ))
        rows = cur.fetchall()
    return [dict(r) for r in rows]

# 5-2. 我發的任務
@router.get("/my/owner")
def get_my_post_bounty(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT id, title, description, reward, taker
            FROM bounty
            WHERE owner = ?
            ORDER BY id DESC
        """, (account, ))
        rows = cur.fetchall()
    return [dict(r) for r in rows]

# 6. 刪除任務
@router.delete("/{id}")
def delete_task(id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        # 重要：這裡加了 AND account = ? 是為了安全！
        # 確保你只能刪除「你自己」的任務，不能刪別人的
        cur.execute(
            "DELETE FROM bounty WHERE id = ? AND owner = ?", 
            (id, account)
        )
        conn.commit()
        
        # 檢查有沒有真的刪除到資料 (若 rowcount 為 0 表示找不到該 ID 或是該 ID 不屬於你)
        if cur.rowcount == 0:
            return {"success": False, "message": "刪除失敗，任務不存在或無權限"}

    return {"success": True, "message": "任務已刪除"}

# 7. 修改任務 (編輯)
@router.put("/{id}")
def update_task(id: int, bounty: Bounty, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        # 先檢查任務是否存在，且是這個人的
        cur.execute("SELECT id FROM bounty WHERE id = ? AND owner = ?", (id, account))
        if not cur.fetchone():
             raise HTTPException(status_code=404, detail="任務不存在或無權限")

        # 更新資料
        cur.execute("UPDATE bounty SET title = ?, description = ?, reward = ? WHERE id = ? AND owner = ?",
            (bounty.title, bounty.description, bounty.reward, id, account))
        conn.commit()
    return {"success": True, "message": "任務已更新"}