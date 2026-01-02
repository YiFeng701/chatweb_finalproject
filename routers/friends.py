from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
import sqlite3
from dependencies import get_user
from typing import List, Optional
from datetime import datetime

router = APIRouter(
    prefix="/friends",
    tags=["好友系統"]
)

class FriendRequest(BaseModel):
    friend_account: str

class PrivateMessage(BaseModel):
    receiver_account: str
    content: str

# 1. 發送好友請求
@router.post("/request")
def send_friend_request(request: FriendRequest, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    if account == request.friend_account:
        raise HTTPException(status_code=400, detail="不能加自己為好友")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        
        # 檢查對方是否存在
        cur.execute("SELECT account FROM users WHERE account = ?", (request.friend_account,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="使用者不存在")
        
        # 檢查是否已經是好友或已有待處理請求
        cur.execute("""
            SELECT status FROM friends 
            WHERE (user_account = ? AND friend_account = ?) 
               OR (user_account = ? AND friend_account = ?)
        """, (account, request.friend_account, request.friend_account, account))
        
        existing = cur.fetchone()
        if existing:
            if existing[0] == 'accepted':
                raise HTTPException(status_code=400, detail="已經是好友")
            elif existing[0] == 'pending':
                raise HTTPException(status_code=400, detail="已發送好友請求")
            elif existing[0] == 'blocked':
                raise HTTPException(status_code=400, detail="無法發送請求")
        
        # 插入好友請求
        cur.execute(
            "INSERT INTO friends (user_account, friend_account, status) VALUES (?, ?, 'pending')",
            (account, request.friend_account)
        )
        conn.commit()
    
    return {"success": True, "message": "好友請求已發送"}

# 2. 接受好友請求
@router.post("/accept/{friend_account}")
def accept_friend_request(friend_account: str, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        
        # 檢查是否有待處理的請求
        cur.execute("""
            SELECT id FROM friends 
            WHERE user_account = ? AND friend_account = ? AND status = 'pending'
        """, (friend_account, account))
        
        if not cur.fetchone():
            raise HTTPException(status_code=400, detail="沒有待處理的好友請求")
        
        # 更新狀態為 accepted，並建立雙向關係
        cur.execute("""
            UPDATE friends SET status = 'accepted' 
            WHERE user_account = ? AND friend_account = ?
        """, (friend_account, account))
        
        # 檢查反向關係是否存在
        cur.execute("""
            SELECT id FROM friends 
            WHERE user_account = ? AND friend_account = ?
        """, (account, friend_account))
        
        if not cur.fetchone():
            # 建立反向好友關係
            cur.execute("""
                INSERT INTO friends (user_account, friend_account, status) 
                VALUES (?, ?, 'accepted')
            """, (account, friend_account))
        
        conn.commit()
    
    return {"success": True, "message": "好友請求已接受"}

# 3. 拒絕好友請求
@router.post("/reject/{friend_account}")
def reject_friend_request(friend_account: str, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM friends WHERE user_account = ? AND friend_account = ?", 
                   (friend_account, account))
        conn.commit()
    
    return {"success": True, "message": "好友請求已拒絕"}

# 4. 取得好友列表
@router.get("/list")
def get_friends_list(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT u.account, u.name, f.created_at
            FROM friends f
            JOIN users u ON f.friend_account = u.account
            WHERE f.user_account = ? AND f.status = 'accepted'
            ORDER BY u.name
        """, (account,))
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]

# 5. 取得待處理的好友請求
@router.get("/requests")
def get_pending_requests(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT u.account, u.name, f.created_at
            FROM friends f
            JOIN users u ON f.user_account = u.account
            WHERE f.friend_account = ? AND f.status = 'pending'
            ORDER BY f.created_at DESC
        """, (account,))
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]

# 6. 刪除好友
@router.delete("/{friend_account}")
def delete_friend(friend_account: str, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        # 刪除雙向好友關係
        cur.execute("DELETE FROM friends WHERE (user_account = ? AND friend_account = ?) OR (user_account = ? AND friend_account = ?)", 
                   (account, friend_account, friend_account, account))
        conn.commit()
    
    return {"success": True, "message": "好友已刪除"}

# 7. 搜尋使用者
@router.get("/search")
def search_users(query: str, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT account, name 
            FROM users 
            WHERE (account LIKE ? OR name LIKE ?) AND account != ?
            LIMIT 20
        """, (f"%{query}%", f"%{query}%", account))
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]

# 8. 發送私訊
@router.post("/message")
async def send_private_message(message: PrivateMessage, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    if account == message.receiver_account:
        raise HTTPException(status_code=400, detail="不能傳送訊息給自己")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        
        # 檢查對方是否存在
        cur.execute("SELECT account FROM users WHERE account = ?", (message.receiver_account,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="使用者不存在")
        
        # 插入私訊
        cur.execute("""
            INSERT INTO private_messages (sender_account, receiver_account, content) 
            VALUES (?, ?, ?)
        """, (account, message.receiver_account, message.content))
        
        conn.commit()
    
    # 嘗試透過 WebSocket 即時推送訊息
    try:
        from main import manager
        await manager.send_personal(message.receiver_account, account, message.content)
    except Exception as e:
        # WebSocket 推送失敗，訊息已儲存到資料庫，使用者下次載入時能看到
        print(f"WebSocket 推送失敗（接收者可能離線）: {e}")
    
    return {"success": True, "message": "私訊已發送"}

# 9. 取得私訊歷史
@router.get("/messages/{friend_account}")
def get_private_messages(friend_account: str, limit: int = 50, account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # 取得與指定好友的私訊
        cur.execute("""
            SELECT 
                pm.sender_account,
                pm.receiver_account,
                pm.content,
                pm.is_read,
                pm.created_at,
                sender.name as sender_name,
                receiver.name as receiver_name
            FROM private_messages pm
            JOIN users sender ON pm.sender_account = sender.account
            JOIN users receiver ON pm.receiver_account = receiver.account
            WHERE (pm.sender_account = ? AND pm.receiver_account = ?)
               OR (pm.sender_account = ? AND pm.receiver_account = ?)
            ORDER BY pm.created_at DESC
            LIMIT ?
        """, (account, friend_account, friend_account, account, limit))
        
        rows = cur.fetchall()
        
        # 標記訊息為已讀
        cur.execute("""
            UPDATE private_messages 
            SET is_read = 1 
            WHERE receiver_account = ? AND sender_account = ? AND is_read = 0
        """, (account, friend_account))
        conn.commit()
    
    messages = [dict(row) for row in rows]
    messages.reverse()  # 按時間順序排列
    
    return messages

# 10. 取得未讀訊息數量
@router.get("/unread/count")
def get_unread_count(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT COUNT(*) as count
            FROM private_messages
            WHERE receiver_account = ? AND is_read = 0
        """, (account,))
        count = cur.fetchone()[0]
    
    return {"unread_count": count}

# 11. 取得最近對話列表
@router.get("/conversations")
def get_recent_conversations(account: str = Depends(get_user)):
    if not account:
        raise HTTPException(status_code=401, detail="請先登入")
    
    with sqlite3.connect("user.db") as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT 
                other_account,
                u.name as other_name,
                pm.content as last_message,
                last_time,
                unread_count
            FROM (
                SELECT 
                    CASE 
                        WHEN sender_account = ? THEN receiver_account
                        ELSE sender_account
                    END as other_account,
                    MAX(created_at) as last_time,
                    SUM(CASE WHEN receiver_account = ? AND is_read = 0 THEN 1 ELSE 0 END) as unread_count
                FROM private_messages
                WHERE sender_account = ? OR receiver_account = ?
                GROUP BY other_account
            ) r
            JOIN private_messages pm
                ON (
                    (pm.sender_account = r.other_account AND pm.receiver_account = ?)
                    OR
                    (pm.sender_account = ? AND pm.receiver_account = r.other_account)
                )
                AND pm.created_at = r.last_time
            JOIN users u ON r.other_account = u.account
            ORDER BY r.last_time DESC
        """, (account, account, account, account, account, account))
        
        rows = cur.fetchall()
    
    return [dict(row) for row in rows]