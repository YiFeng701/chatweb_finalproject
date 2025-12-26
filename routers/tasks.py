from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
from dependencies import get_user
from typing import Optional

# 建立一個路由器
router = APIRouter(
    prefix="/tasks",    # 網址前綴，之後所有 API 都會是 /tasks/xxx
    tags=["任務管理"]    # 在 API 文件裡的分類標籤
)

# 定義傳入的資料格式
class TaskModel(BaseModel):
    title: str
    description: Optional[str] = None  # 允許是空的
    deadline: Optional[str] = None     # 允許是空的
    is_completed: bool = False

# 1. 新增任務
@router.post("/")
def create_task(task: TaskModel, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
        
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO tasks (account, title, description, deadline, is_completed) 
               VALUES (?, ?, ?, ?, ?)""",
            (account, task.title, task.description, task.deadline, task.is_completed)
        )
        conn.commit()
    return {"success": True, "message": "任務已新增"}
# 2. 取得我的任務列表
@router.get("/")
def get_my_tasks(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        # 修改這裡：加入 ORDER BY is_completed ASC, id DESC
        # 解釋：is_completed (0在前, 1在後)，id DESC (新的在前)
        cur.execute("""
            SELECT * FROM tasks 
            WHERE account = ? 
            ORDER BY is_completed ASC, id DESC
        """, (account,))
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]

# 2. 新增：切換任務完成狀態 (PUT 方法)
@router.put("/{task_id}/toggle")
def toggle_task(task_id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        # 先檢查任務目前的狀態
        cur.execute("SELECT is_completed FROM tasks WHERE id = ? AND account = ?", (task_id, account))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="任務不存在")
        
        # 狀態反轉：如果是 0 變 1，是 1 變 0
        new_status = not row[0]
        
        cur.execute("UPDATE tasks SET is_completed = ? WHERE id = ? AND account = ?", (new_status, task_id, account))
        conn.commit()

    return {"success": True, "message": "狀態已更新"}
# ... 上面是原本的 create_task 和 get_my_tasks ...

# 3. 刪除任務
@router.delete("/{task_id}")
def delete_task(task_id: int, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")

    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        # 重要：這裡加了 AND account = ? 是為了安全！
        # 確保你只能刪除「你自己」的任務，不能刪別人的
        cur.execute(
            "DELETE FROM tasks WHERE id = ? AND account = ?", 
            (task_id, account)
        )
        conn.commit()
        
        # 檢查有沒有真的刪除到資料 (若 rowcount 為 0 表示找不到該 ID 或是該 ID 不屬於你)
        if cur.rowcount == 0:
            return {"success": False, "message": "刪除失敗，任務不存在或無權限"}

    return {"success": True, "message": "任務已刪除"}