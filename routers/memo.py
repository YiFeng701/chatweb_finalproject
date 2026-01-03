from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
from dependencies import get_user
from typing import Optional

router = APIRouter(
    prefix="/memos",
    tags=["備忘錄管理"]
)

# 定義傳入的資料格式
class MemoModel(BaseModel):
    title: str
    content: Optional[str] = None  # 內容
    deadline: Optional[str] = None # 加回：截止日期
    is_completed: bool = False     # 加回：預設為未完成

# 1. 新增備忘錄 (包含日期與狀態)
@router.post("/")
def create_memo(memo: MemoModel, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
        
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO memos (account, title, content, deadline, is_completed) 
               VALUES (?, ?, ?, ?, ?)""",
            (account, memo.title, memo.content, memo.deadline, memo.is_completed)
        )
        conn.commit()
    return {"success": True, "message": "備忘錄已新增"}

# 2. 取得列表 (未完成的在上面)
@router.get("/")
def get_my_memos(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # 排序邏輯恢復：未完成 (0) 先排，然後照 ID 倒序
        cur.execute("""
            SELECT * FROM memos 
            WHERE account = ? 
            ORDER BY is_completed ASC, id DESC
        """, (account,))
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]

# 3. [加回] 切換完成狀態 (打勾/取消打勾)
@router.put("/{memo_id}/toggle")
def toggle_memo(memo_id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT is_completed FROM memos WHERE id = ? AND account = ?", (memo_id, account))
        row = cur.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="備忘錄不存在")
        
        # 狀態反轉
        new_status = not row[0]
        
        cur.execute("UPDATE memos SET is_completed = ? WHERE id = ? AND account = ?", (new_status, memo_id, account))
        conn.commit()

    return {"success": True, "message": "狀態已更新"}

# 4. 修改備忘錄 (內容與日期)
@router.put("/{memo_id}")
def update_memo(memo_id: int, memo: MemoModel, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM memos WHERE id = ? AND account = ?", (memo_id, account))
        if not cur.fetchone():
             raise HTTPException(status_code=404, detail="備忘錄不存在或無權限")

        # 更新：包含 deadline
        cur.execute(
            """UPDATE memos 
               SET title = ?, content = ?, deadline = ?
               WHERE id = ? AND account = ?""",
            (memo.title, memo.content, memo.deadline, memo_id, account)
        )
        conn.commit()
    return {"success": True, "message": "備忘錄已更新"}

# 5. 刪除備忘錄
@router.delete("/{memo_id}")
def delete_memo(memo_id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute(
            "DELETE FROM memos WHERE id = ? AND account = ?", 
            (memo_id, account)
        )
        conn.commit()
        
        if cur.rowcount == 0:
            return {"success": False, "message": "刪除失敗"}

    return {"success": True, "message": "備忘錄已刪除"}