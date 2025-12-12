from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import json
import uuid
from datetime import datetime
import os
import logging
import hashlib

# 配置日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# 数据文件路径
DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")
DOCUMENTS_FILE = os.path.join(DATA_DIR, "documents.json")
AUDIT_LOGS_FILE = os.path.join(DATA_DIR, "audit_logs.json")

# 确保数据目录存在
os.makedirs(DATA_DIR, exist_ok=True)

def load_data(file_path, default_data):
    """从文件加载数据，如果文件不存在则使用默认数据"""
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"加载数据文件 {file_path} 失败: {e}")
    return default_data.copy() if hasattr(default_data, 'copy') else default_data

def save_data(file_path, data):
    """保存数据到文件"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        logger.error(f"保存数据到 {file_path} 失败: {e}")
        return False

# 默认用户数据
DEFAULT_USERS = [
    # 2个特殊用户
    {"id": "1", "username": "special_user1", "password": "special_password1", "permission": "special", "can_upgrade": True},
    {"id": "2", "username": "special_user2", "password": "special_password2", "permission": "special", "can_upgrade": True},
    
    # 3个绝密用户
    {"id": "3", "username": "ts_user1", "password": "ts_password1", "permission": "top_secret", "can_upgrade": True},
    {"id": "4", "username": "ts_user2", "password": "ts_password2", "permission": "top_secret", "can_upgrade": True},
    {"id": "5", "username": "ts_user3", "password": "ts_password3", "permission": "top_secret", "can_upgrade": True},
    
    # 12个机密用户
    {"id": "6", "username": "c_user1", "password": "c_password1", "permission": "confidential", "can_upgrade": False},
    {"id": "7", "username": "c_user2", "password": "c_password2", "permission": "confidential", "can_upgrade": False},
    {"id": "8", "username": "c_user3", "password": "c_password3", "permission": "confidential", "can_upgrade": False},
    {"id": "9", "username": "c_user4", "password": "c_password4", "permission": "confidential", "can_upgrade": False},
    {"id": "10", "username": "c_user5", "password": "c_password5", "permission": "confidential", "can_upgrade": False},
    {"id": "11", "username": "c_user6", "password": "c_password6", "permission": "confidential", "can_upgrade": False},
    {"id": "12", "username": "c_user7", "password": "c_password7", "permission": "confidential", "can_upgrade": False},
    {"id": "13", "username": "c_user8", "password": "c_password8", "permission": "confidential", "can_upgrade": False},
    {"id": "14", "username": "c_user9", "password": "c_password9", "permission": "confidential", "can_upgrade": False},
    {"id": "15", "username": "c_user10", "password": "c_password10", "permission": "confidential", "can_upgrade": False},
    {"id": "16", "username": "c_user11", "password": "c_password11", "permission": "confidential", "can_upgrade": False},
    {"id": "17", "username": "c_user12", "password": "c_password12", "permission": "confidential", "can_upgrade": False},
    
    # 9个普通用户
    {"id": "18", "username": "normal_user1", "password": "normal_password1", "permission": "normal", "can_upgrade": False},
    {"id": "19", "username": "normal_user2", "password": "normal_password2", "permission": "normal", "can_upgrade": False},
    {"id": "20", "username": "normal_user3", "password": "normal_password3", "permission": "normal", "can_upgrade": False},
    {"id": "21", "username": "normal_user4", "password": "normal_password4", "permission": "normal", "can_upgrade": False},
    {"id": "22", "username": "normal_user5", "password": "normal_password5", "permission": "normal", "can_upgrade": False},
    {"id": "23", "username": "normal_user6", "password": "normal_password6", "permission": "normal", "can_upgrade": False},
    {"id": "24", "username": "normal_user7", "password": "normal_password7", "permission": "normal", "can_upgrade": False},
    {"id": "25", "username": "normal_user8", "password": "normal_password8", "permission": "normal", "can_upgrade": False},
    {"id": "26", "username": "normal_user9", "password": "normal_password9", "permission": "normal", "can_upgrade": False}
]

# 默认文档数据
DEFAULT_DOCUMENTS = [
    {
        "id": "1",
        "filename": "普通通知.txt",
        "permission": "normal", 
        "content": "这是一份普通通知文档，所有用户都可以查看。\n\n主要内容：\n1. 系统使用说明\n2. 权限管理规则\n3. 安全操作指南",
        "created_at": "2024-01-01",
        "created_by": "system"
    },
    {
        "id": "2",
        "filename": "部门会议纪要.docx", 
        "permission": "confidential",
        "content": "机密会议纪要内容，包含重要商业决策。\n\n会议主题：2024年战略规划\n参会人员：管理层全体\n决议事项：\n1. 新产品开发计划\n2. 市场拓展策略\n3. 预算分配方案",
        "created_at": "2024-01-01",
        "created_by": "system"
    },
    {
        "id": "3",
        "filename": "公司战略规划.pdf",
        "permission": "top_secret", 
        "content": "绝密战略规划文档，包含公司未来5年发展规划。\n\n核心内容：\n1. 技术研发路线图\n2. 市场竞争分析\n3. 投资并购计划\n4. 风险控制策略\n5. 应急预案",
        "created_at": "2024-01-01", 
        "created_by": "system"
    },
    {
        "id": "4",
        "filename": "国家安全级别文档.sec",
        "permission": "special", 
        "content": "特殊权限文档，包含最高级别机密信息。\n\n访问限制：\n- 仅限特殊权限用户访问\n- 包含国家级安全信息\n- 严格审计追踪\n\n内容分类：\n1. 国家安全战略\n2. 关键基础设施保护\n3. 紧急响应预案",
        "created_at": "2024-01-01", 
        "created_by": "system"
    },
    {
        "id": "5",
        "filename": "技术研发白皮书.pdf",
        "permission": "confidential",
        "content": "机密技术研发文档。\n\n研发方向：\n1. 人工智能算法优化\n2. 量子计算研究\n3. 网络安全防护\n4. 数据加密技术",
        "created_at": "2024-01-01",
        "created_by": "system"
    }
]

# 加载数据
users = load_data(USERS_FILE, DEFAULT_USERS)
documents = load_data(DOCUMENTS_FILE, DEFAULT_DOCUMENTS)
audit_logs = load_data(AUDIT_LOGS_FILE, [])

# 会话管理（内存中，重启会丢失）
user_sessions = {}

def create_session(user):
    """创建用户会话"""
    session_id = str(uuid.uuid4())
    user_sessions[session_id] = {
        'user_id': user['id'],
        'username': user['username'],
        'permission': user['permission'],
        'can_upgrade': user.get('can_upgrade', False),
        'created_at': datetime.now().isoformat()
    }
    return session_id

def get_session(session_id):
    """获取会话信息"""
    return user_sessions.get(session_id)

def get_permission_level(permission):
    """获取权限等级数值"""
    levels = {"normal": 1, "confidential": 2, "top_secret": 3, "special": 4}
    return levels.get(permission, 0)

def get_permission_text(permission):
    """获取权限文本描述"""
    texts = {
        "normal": "普通",
        "confidential": "机密", 
        "top_secret": "绝密",
        "special": "特殊"
    }
    return texts.get(permission, permission)

def hash_password(password):
    """哈希密码（可选，当前系统使用明文）"""
    return hashlib.sha256(password.encode()).hexdigest()

def log_audit(username, action, details):
    """记录审计日志并保存到文件"""
    audit_entry = {
        "id": str(uuid.uuid4()),
        "timestamp": datetime.now().isoformat(),
        "username": username,
        "action": action,
        "details": details,
        "ip": request.remote_addr if request else "0.0.0.0"
    }
    audit_logs.append(audit_entry)
    
    # 只保留最近1000条日志
    if len(audit_logs) > 1000:
        audit_logs.pop(0)
    
    # 异步保存审计日志
    save_data(AUDIT_LOGS_FILE, audit_logs)
    
    logger.info(f"审计日志: {username} - {action}")

def save_users():
    """保存用户数据"""
    return save_data(USERS_FILE, users)

def save_documents():
    """保存文档数据"""
    return save_data(DOCUMENTS_FILE, documents)

# ==================== API路由 ====================

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "安全文档库系统",
        "version": "3.1",
        "user_count": len(users),
        "document_count": len(documents),
        "audit_log_count": len(audit_logs),
        "data_persistence": True,
        "permission_levels": ["特殊", "绝密", "机密", "普通"]
    })

@app.route('/api/login', methods=['POST'])
def login():
    """用户登录"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({"error": "用户名和密码不能为空"}), 400

        user = next((u for u in users if u['username'] == username), None)
        
        if not user:
            return jsonify({"error": "用户名或密码错误"}), 401

        # 直接比较明文密码
        if user['password'] != password:
            return jsonify({"error": "用户名或密码错误"}), 401

        # 创建会话
        session_id = create_session(user)

        # 记录登录日志
        log_audit(username, "用户登录", "成功登录系统")

        return jsonify({
            "session_id": session_id,
            "user": {
                "id": user['id'],
                "username": user['username'],
                "permission": user['permission'],
                "can_upgrade": user.get('can_upgrade', False)
            }
        })
    except Exception as e:
        logger.error(f"登录处理异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/emergency-upgrade', methods=['POST'])
def emergency_upgrade():
    """紧急权限升级"""
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        emergency_password = data.get('emergency_password')
        
        if emergency_password != 'hello':
            return jsonify({"error": "紧急升级密码错误"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        # 找到用户并升级权限
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if not user:
            return jsonify({"error": "用户不存在"}), 404

        old_permission = user['permission']
        user['permission'] = 'special'  # 紧急升级到特殊权限
        user['can_upgrade'] = True

        # 更新会话
        session['permission'] = 'special'
        session['can_upgrade'] = True

        # 保存用户数据
        save_users()

        log_audit(session['username'], "紧急权限升级", f"从 {old_permission} 升级到 special")

        return jsonify({
            "message": "紧急权限升级成功！您现在拥有特殊权限。",
            "user": {
                "id": user['id'],
                "username": user['username'],
                "permission": user['permission'],
                "can_upgrade": user['can_upgrade']
            }
        })
    except Exception as e:
        logger.error(f"紧急升级处理异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/documents', methods=['GET'])
def get_documents():
    """获取文档列表（根据权限过滤）"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        user_level = get_permission_level(session['permission'])
        
        accessible_docs = [
            {
                "id": doc["id"],
                "filename": doc["filename"],
                "permission": doc["permission"],
                "permission_text": get_permission_text(doc["permission"]),
                "created_at": doc["created_at"],
                "created_by": doc["created_by"]
            }
            for doc in documents 
            if user_level >= get_permission_level(doc['permission'])
        ]

        return jsonify(accessible_docs)
    except Exception as e:
        logger.error(f"获取文档列表异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/documents/<document_id>', methods=['GET'])
def get_document_content(document_id):
    """获取单个文档内容"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        document = next((doc for doc in documents if doc['id'] == document_id), None)
        if not document:
            return jsonify({"error": "文档不存在"}), 404

        user_level = get_permission_level(session['permission'])
        doc_level = get_permission_level(document['permission'])
        
        if user_level < doc_level:
            return jsonify({"error": "权限不足"}), 403

        log_audit(session['username'], "查看文档", f"查看文档: {document['filename']}")

        return jsonify(document)
    except Exception as e:
        logger.error(f"获取文档内容异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500


@app.route('/api/documents/<document_id>', methods=['DELETE'])
def delete_document(document_id):
    """删除文档"""
    try:
        global documents  # 将 global 声明移到函数最开头
        
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        # 找到要删除的文档
        document = next((doc for doc in documents if doc['id'] == document_id), None)
        if not document:
            return jsonify({"error": "文档不存在"}), 404

        # 权限检查：只有文档创建者或特殊权限用户可以删除
        user_can_delete = (
            session['username'] == document['created_by'] or  # 文档创建者
            session['permission'] == 'special' or  # 特殊权限用户
            (session['permission'] == 'top_secret' and document['permission'] != 'special')  # 绝密用户可以删除非特殊文档
        )
        
        if not user_can_delete:
            return jsonify({"error": "权限不足，无法删除此文档"}), 403

        # 从文档列表中移除
        original_length = len(documents)
        documents = [doc for doc in documents if doc['id'] != document_id]
        
        if len(documents) == original_length:
            return jsonify({"error": "删除失败，文档不存在"}), 404

        # 保存文档数据
        save_documents()

        log_audit(session['username'], "删除文档", f"删除文档: {document['filename']} (ID: {document_id})")

        return jsonify({
            "message": "文档删除成功",
            "deleted_document": {
                "id": document_id,
                "filename": document['filename']
            }
        })
    except Exception as e:
        logger.error(f"删除文档异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/documents', methods=['POST'])
def add_document():
    """添加新文档"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        # 只有特殊和绝密用户可以添加文档
        if session['permission'] not in ['special', 'top_secret']:
            return jsonify({"error": "权限不足，只有特殊和绝密用户可以添加文档"}), 403

        data = request.get_json()
        if not data.get('filename') or not data.get('content'):
            return jsonify({"error": "文档名称和内容不能为空"}), 400

        # 特殊用户可创建所有权限文档，绝密用户只能创建机密和普通文档
        user_permission = session['permission']
        doc_permission = data.get('permission', 'normal')
        
        if user_permission == 'top_secret' and doc_permission in ['special', 'top_secret']:
            return jsonify({"error": "绝密用户只能创建机密和普通权限文档"}), 403

        new_doc = {
            "id": str(uuid.uuid4()),
            "filename": data['filename'],
            "permission": doc_permission,
            "content": data['content'],
            "created_at": datetime.now().strftime('%Y-%m-%d'),
            "created_by": session['username']
        }

        documents.append(new_doc)

        # 保存文档数据
        save_documents()

        log_audit(session['username'], "添加文档", f"添加文档: {data['filename']}, 权限: {doc_permission}")

        return jsonify(new_doc)
    except Exception as e:
        logger.error(f"添加文档异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/users', methods=['GET'])
def get_users():
    """获取用户列表（特殊权限用户可见）"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        if not session.get('can_upgrade', False):
            return jsonify({"error": "权限不足"}), 403

        other_users = [
            {
                "id": u["id"],
                "username": u["username"],
                "permission": u["permission"],
                "permission_text": get_permission_text(u["permission"]),
                "can_upgrade": u.get("can_upgrade", False)
            }
            for u in users if u['id'] != session['user_id']
        ]
        return jsonify(other_users)
    except Exception as e:
        logger.error(f"获取用户列表异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/users/<user_id>/permission', methods=['PUT'])
def update_user_permission(user_id):
    """更新用户权限"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        if not session.get('can_upgrade', False):
            return jsonify({"error": "权限不足"}), 403

        data = request.get_json()
        new_permission = data.get('permission')
        
        if new_permission not in ['normal', 'confidential', 'top_secret', 'special']:
            return jsonify({"error": "无效的权限等级"}), 400

        target_user = next((u for u in users if u['id'] == user_id), None)
        if not target_user:
            return jsonify({"error": "用户不存在"}), 404

        old_permission = target_user['permission']
        target_user['permission'] = new_permission
        
        # 特殊权限用户才能管理其他用户权限
        if new_permission == 'special':
            target_user['can_upgrade'] = True
        else:
            target_user['can_upgrade'] = False

        # 保存用户数据
        save_users()

        log_audit(session['username'], "权限变更", f"将用户 {target_user['username']} 从 {old_permission} 改为 {new_permission}")

        return jsonify({
            "id": target_user['id'],
            "username": target_user['username'],
            "permission": target_user['permission'],
            "permission_text": get_permission_text(target_user['permission']),
            "can_upgrade": target_user.get('can_upgrade', False)
        })
    except Exception as e:
        logger.error(f"更新用户权限异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/audit-logs', methods=['GET'])
def get_audit_logs():
    """获取审计日志"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        if session['permission'] not in ['special', 'top_secret']:
            return jsonify({"error": "权限不足"}), 403

        return jsonify(audit_logs[-100:])  # 返回最近100条日志
    except Exception as e:
        logger.error(f"获取审计日志异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    """修改用户密码"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        data = request.get_json()
        old_password = data.get('old_password')
        new_password = data.get('new_password')
        confirm_password = data.get('confirm_password')

        if not all([old_password, new_password, confirm_password]):
            return jsonify({"error": "所有字段都必须填写"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "新密码和确认密码不匹配"}), 400

        if len(new_password) < 6:
            return jsonify({"error": "新密码至少需要6个字符"}), 400

        # 找到当前用户
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if not user:
            return jsonify({"error": "用户不存在"}), 404

        # 验证旧密码
        if user['password'] != old_password:
            return jsonify({"error": "旧密码不正确"}), 401

        # 更新密码
        user['password'] = new_password
        
        # 保存用户数据
        save_users()

        log_audit(session['username'], "更改密码", "密码已更新")

        return jsonify({
            "message": "密码修改成功"
        })
    except Exception as e:
        logger.error(f"修改密码异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/backup', methods=['GET'])
def backup_data():
    """备份所有数据（特殊权限用户可用）"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        if session['permission'] != 'special':
            return jsonify({"error": "需要特殊权限"}), 403

        backup_data = {
            "timestamp": datetime.now().isoformat(),
            "users": users,
            "documents": documents,
            "audit_logs": audit_logs[-500:]  # 只备份最近500条日志
        }

        # 保存备份文件
        backup_file = os.path.join(DATA_DIR, f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(backup_file, 'w', encoding='utf-8') as f:
            json.dump(backup_data, f, ensure_ascii=False, indent=2)

        log_audit(session['username'], "数据备份", f"创建备份文件: {backup_file}")

        return jsonify({
            "message": "数据备份成功",
            "backup_file": backup_file,
            "backup_time": datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"数据备份异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """获取系统统计信息"""
    try:
        session_id = request.headers.get('Authorization')
        if not session_id:
            return jsonify({"error": "未授权"}), 401

        session = get_session(session_id)
        if not session:
            return jsonify({"error": "会话无效"}), 401

        # 统计各权限用户数量
        permission_counts = {
            "special": 0,
            "top_secret": 0,
            "confidential": 0,
            "normal": 0
        }
        
        for user in users:
            if user['permission'] in permission_counts:
                permission_counts[user['permission']] += 1

        # 统计各权限文档数量
        doc_counts = {
            "special": 0,
            "top_secret": 0,
            "confidential": 0,
            "normal": 0
        }
        
        for doc in documents:
            if doc['permission'] in doc_counts:
                doc_counts[doc['permission']] += 1

        return jsonify({
            "user_stats": {
                "total": len(users),
                "by_permission": permission_counts
            },
            "document_stats": {
                "total": len(documents),
                "by_permission": doc_counts
            },
            "audit_logs": len(audit_logs),
            "data_files": {
                "users": os.path.getsize(USERS_FILE) if os.path.exists(USERS_FILE) else 0,
                "documents": os.path.getsize(DOCUMENTS_FILE) if os.path.exists(DOCUMENTS_FILE) else 0,
                "audit_logs": os.path.getsize(AUDIT_LOGS_FILE) if os.path.exists(AUDIT_LOGS_FILE) else 0
            }
        })
    except Exception as e:
        logger.error(f"获取统计信息异常: {e}")
        return jsonify({"error": "服务器内部错误"}), 500

# ==================== 前端页面路由 ====================

@app.route('/')
def index():
    """返回前端页面"""
    try:
        # 尝试返回前端页面
        return """
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>安全文档库管理系统 v3.1</title>
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }

                body {
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    padding: 20px;
                }

                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    overflow: hidden;
                }

                /* 头部样式 */
                header {
                    background: linear-gradient(90deg, #2c3e50, #4a6491);
                    color: white;
                    padding: 25px 40px;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .logo {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }

                .logo h1 {
                    font-size: 24px;
                    font-weight: 600;
                }

                .logo .version {
                    background: rgba(255,255,255,0.2);
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: normal;
                }

                .data-badge {
                    background: #28a745;
                    padding: 6px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: bold;
                    margin-left: 10px;
                }

                .user-info {
                    display: flex;
                    align-items: center;
                    gap: 15px;
                }

                .user-badge {
                    background: rgba(255,255,255,0.1);
                    padding: 8px 16px;
                    border-radius: 10px;
                    display: flex;
                    align-items: center;
                    gap: 8px;
                }

                .permission-badge {
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 12px;
                    font-weight: bold;
                }

                .permission-special { background: #8e44ad; }
                .permission-top-secret { background: #c0392b; }
                .permission-confidential { background: #f39c12; }
                .permission-normal { background: #27ae60; }

                /* 主内容区 */
                .main-content {
                    display: flex;
                    min-height: 600px;
                }

                /* 侧边栏 */
                .sidebar {
                    width: 250px;
                    background: #f8f9fa;
                    border-right: 1px solid #e9ecef;
                    padding: 25px;
                }

                .nav-item {
                    padding: 12px 15px;
                    margin: 5px 0;
                    border-radius: 10px;
                    cursor: pointer;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                    transition: all 0.3s;
                    color: #495057;
                }

                .nav-item:hover {
                    background: #e9ecef;
                }

                .nav-item.active {
                    background: #007bff;
                    color: white;
                }

                .nav-item i {
                    width: 20px;
                    text-align: center;
                }

                /* 内容区 */
                .content {
                    flex: 1;
                    padding: 30px;
                }

                /* 卡片样式 */
                .card {
                    background: white;
                    border-radius: 15px;
                    padding: 25px;
                    box-shadow: 0 5px 20px rgba(0,0,0,0.08);
                    margin-bottom: 25px;
                    display: none;
                }

                .card.active {
                    display: block;
                    animation: fadeIn 0.5s;
                }

                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }

                .card-title {
                    font-size: 20px;
                    font-weight: 600;
                    color: #2c3e50;
                    margin-bottom: 20px;
                    display: flex;
                    align-items: center;
                    gap: 10px;
                }

                /* 表格样式 */
                .table-container {
                    overflow-x: auto;
                    border-radius: 10px;
                    border: 1px solid #e9ecef;
                }

                table {
                    width: 100%;
                    border-collapse: collapse;
                }

                th {
                    background: #f8f9fa;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    color: #495057;
                    border-bottom: 2px solid #e9ecef;
                }

                td {
                    padding: 15px;
                    border-bottom: 1px solid #e9ecef;
                    vertical-align: top;
                }

                tr:hover {
                    background: #f8f9fa;
                }

                /* 按钮样式 */
                .btn {
                    padding: 10px 20px;
                    border: none;
                    border-radius: 8px;
                    cursor: pointer;
                    font-weight: 600;
                    transition: all 0.3s;
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                }

                .btn-primary {
                    background: #007bff;
                    color: white;
                }

                .btn-primary:hover {
                    background: #0056b3;
                    transform: translateY(-2px);
                }

                .btn-success {
                    background: #28a745;
                    color: white;
                }

                .btn-success:hover {
                    background: #1e7e34;
                    transform: translateY(-2px);
                }

                .btn-danger {
                    background: #dc3545;
                    color: white;
                }

                .btn-danger:hover {
                    background: #c82333;
                    transform: translateY(-2px);
                }

                .btn-warning {
                    background: #ffc107;
                    color: #212529;
                }

                .btn-warning:hover {
                    background: #e0a800;
                    transform: translateY(-2px);
                }

                .btn-sm {
                    padding: 6px 12px;
                    font-size: 14px;
                }

                /* 表单样式 */
                .form-group {
                    margin-bottom: 20px;
                }

                .form-label {
                    display: block;
                    margin-bottom: 8px;
                    font-weight: 600;
                    color: #495057;
                }

                .form-control {
                    width: 100%;
                    padding: 12px 15px;
                    border: 2px solid #e9ecef;
                    border-radius: 8px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }

                .form-control:focus {
                    outline: none;
                    border-color: #007bff;
                }

                .form-row {
                    display: flex;
                    gap: 20px;
                    margin-bottom: 20px;
                }

                .form-row .form-group {
                    flex: 1;
                }

                /* 登录页面 */
                .login-container {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    min-height: 100vh;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                }

                .login-card {
                    background: white;
                    padding: 40px;
                    border-radius: 20px;
                    box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                    width: 100%;
                    max-width: 400px;
                }

                .login-title {
                    text-align: center;
                    margin-bottom: 30px;
                    color: #2c3e50;
                }

                .alert {
                    padding: 15px;
                    border-radius: 10px;
                    margin-bottom: 20px;
                    display: none;
                }

                .alert-success {
                    background: #d4edda;
                    color: #155724;
                    border: 1px solid #c3e6cb;
                }

                .alert-error {
                    background: #f8d7da;
                    color: #721c24;
                    border: 1px solid #f5c6cb;
                }

                .alert-info {
                    background: #d1ecf1;
                    color: #0c5460;
                    border: 1px solid #bee5eb;
                }

                /* 统计卡片 */
                .stats-container {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }

                .stat-card {
                    background: white;
                    padding: 20px;
                    border-radius: 10px;
                    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                    text-align: center;
                }

                .stat-value {
                    font-size: 32px;
                    font-weight: bold;
                    margin: 10px 0;
                }

                .stat-label {
                    color: #6c757d;
                    font-size: 14px;
                }

                .stat-user { color: #007bff; }
                .stat-doc { color: #28a745; }
                .stat-audit { color: #ffc107; }
                .stat-file { color: #6f42c1; }

                /* 模态框 */
                .modal {
                    display: none;
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0,0,0,0.5);
                    z-index: 1000;
                    justify-content: center;
                    align-items: center;
                }

                .modal-content {
                    background: white;
                    border-radius: 15px;
                    width: 90%;
                    max-width: 800px;
                    max-height: 80vh;
                    overflow: hidden;
                    display: flex;
                    flex-direction: column;
                }

                .modal-header {
                    padding: 20px;
                    background: #f8f9fa;
                    border-bottom: 1px solid #e9ecef;
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .modal-body {
                    padding: 20px;
                    overflow-y: auto;
                    flex: 1;
                }

                .modal-footer {
                    padding: 15px 20px;
                    background: #f8f9fa;
                    border-top: 1px solid #e9ecef;
                    text-align: right;
                }

                .close-btn {
                    background: none;
                    border: none;
                    font-size: 24px;
                    cursor: pointer;
                    color: #6c757d;
                }

                /* 响应式设计 */
                @media (max-width: 768px) {
                    .main-content {
                        flex-direction: column;
                    }
                    
                    .sidebar {
                        width: 100%;
                        border-right: none;
                        border-bottom: 1px solid #e9ecef;
                    }
                    
                    .form-row {
                        flex-direction: column;
                        gap: 0;
                    }

                    .stats-container {
                        grid-template-columns: 1fr;
                    }
                }

                /* 图标 */
                .icon {
                    width: 20px;
                    height: 20px;
                    display: inline-block;
                    background-size: contain;
                    background-repeat: no-repeat;
                }

                .icon-doc { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23007bff"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6z"/></svg>'); }
                .icon-add { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org2000/svg" viewBox="0 0 24 24" fill="%2328a745"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z"/></svg>'); }
                .icon-user { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%236c757d"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>'); }
                .icon-audit { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23ffc107"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 10.99h7c-.53 4.12-3.28 7.79-7 8.94V12H5V6.3l7-3.11v8.8z"/></svg>'); }
                .icon-upgrade { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%238e44ad"><path d="M7 14l5-5 5 5H7z"/></svg>'); }
                .icon-logout { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23dc3545"><path d="M17 7l-1.41 1.41L18.17 11H8v2h10.17l-2.58 2.58L17 17l5-5zM4 5h8V3H4c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h8v-2H4V5z"/></svg>'); }
                .icon-delete { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23dc3545"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>'); }
                .icon-stats { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2317a2b8"><path d="M16 11V3H8v6H2v12h20V11h-6zm-6-6h4v14h-4V5zm-6 6h4v8H4v-8zm16 8h-4v-6h4v6z"/></svg>'); }
                .icon-backup { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%2328a745"><path d="M19.35 10.04C18.67 6.59 15.64 4 12 4 9.11 4 6.6 5.64 5.35 8.04 2.34 8.36 0 10.91 0 14c0 3.31 2.69 6 6 6h13c2.76 0 5-2.24 5-5 0-2.64-2.05-4.78-4.65-4.96zM14 13v4h-4v-4H7l5-5 5 5h-3z"/></svg>'); }
                .icon-data { background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="%23007bff"><path d="M19 3H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM9 17H7v-7h2v7zm4 0h-2V7h2v10zm4 0h-2v-4h2v4z"/></svg>'); }
            </style>
        </head>
        <body>
            <!-- 登录页面 -->
            <div id="loginPage" class="login-container">
                <div class="login-card">
                    <h1 class="login-title">安全文档库管理系统 v3.1</h1>
                    <div class="alert alert-info" style="display: block;">
                        <strong>数据持久化已启用</strong> - 所有数据自动保存，服务器重启不会丢失
                    </div>
                    <div id="loginAlert" class="alert"></div>
                    <form id="loginForm">
                        <div class="form-group">
                            <label class="form-label">用户名</label>
                            <input type="text" id="username" class="form-control" placeholder="请输入用户名" required>
                        </div>
                        <div class="form-group">
                            <label class="form-label">密码</label>
                            <input type="password" id="password" class="form-control" placeholder="请输入密码" required>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; padding: 15px;">
                            登录
                        </button>
                    </form>
                    
                    <div style="margin-top: 30px; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                        <h4 style="margin-bottom: 15px;">测试账户</h4>
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                            <div>
                                <strong>特殊用户:</strong><br>
                                special_user1<br>
                                special_password1
                            </div>
                            <div>
                                <strong>绝密用户:</strong><br>
                                ts_user1<br>
                                ts_password1
                            </div>
                            <div>
                                <strong>机密用户:</strong><br>
                                c_user1<br>
                                c_password1
                            </div>
                            <div>
                                <strong>普通用户:</strong><br>
                                normal_user1<br>
                                normal_password1
                            </div>
                        </div>
                        <p style="margin-top: 10px; font-size: 12px; color: #666;">
                            <strong>紧急升级密码:</strong> hello
                        </p>
                    </div>
                </div>
            </div>

            <!-- 主应用页面 -->
            <div id="mainPage" class="container" style="display: none;">
                <header>
                    <div class="logo">
                        <h1>安全文档库管理系统 <span class="version">v3.1</span><span class="data-badge">数据持久化</span></h1>
                    </div>
                    <div class="user-info">
                        <div class="user-badge">
                            <span id="currentUsername">-</span>
                            <span id="currentPermission" class="permission-badge">-</span>
                        </div>
                        <div style="display: flex; gap: 10px;">
                            <button id="emergencyUpgradeBtn" class="btn btn-success btn-sm" style="display: none;">
                                <i class="icon icon-upgrade"></i> 紧急升级
                            </button>
                            <button id="statsBtn" class="btn btn-warning btn-sm">
                                <i class="icon icon-stats"></i> 统计
                            </button>
                            <button id="backupBtn" class="btn btn-success btn-sm" style="display: none;">
                                <i class="icon icon-backup"></i> 备份
                            </button>
                            <button id="logoutBtn" class="btn btn-danger btn-sm">
                                <i class="icon icon-logout"></i> 退出
                            </button>
                        </div>
                    </div>
                </header>

                <div class="main-content">
                    <div class="sidebar">
                        <div class="nav-item active" data-target="documents">
                            <i class="icon icon-doc"></i> 文档管理
                        </div>
                        <div class="nav-item" data-target="addDocument" id="addDocumentNav" style="display: none;">
                            <i class="icon icon-add"></i> 上传文档
                        </div>
                        <div class="nav-item" data-target="userManagement" id="userManagementNav" style="display: none;">
                            <i class="icon icon-user"></i> 用户管理
                        </div>
                        <div class="nav-item" data-target="auditLogs" id="auditLogsNav" style="display: none;">
                            <i class="icon icon-audit"></i> 审计日志
                        </div>
                        <div class="nav-item" data-target="systemStats" id="systemStatsNav" style="display: none;">
                            <i class="icon icon-data"></i> 系统统计
                        </div>
                    </div>

                    <div class="content">
                        <!-- 文档管理卡片 -->
                        <div id="documentsCard" class="card active">
                            <div class="card-title">
                                <i class="icon icon-doc"></i> 文档列表
                                <span id="docCount" class="permission-badge permission-normal">0个文档</span>
                            </div>
                            <div class="table-container">
                                <table id="documentsTable">
                                    <thead>
                                        <tr>
                                            <th>文档名称</th>
                                            <th>权限级别</th>
                                            <th>创建时间</th>
                                            <th>创建者</th>
                                            <th>操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- 文档列表将通过JS动态填充 -->
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- 上传文档卡片 -->
                        <div id="addDocumentCard" class="card">
                            <div class="card-title">
                                <i class="icon icon-add"></i> 上传新文档
                            </div>
                            <form id="addDocumentForm">
                                <div class="form-row">
                                    <div class="form-group">
                                        <label class="form-label">文档名称</label>
                                        <input type="text" id="docFilename" class="form-control" placeholder="例如：会议纪要.docx" required>
                                    </div>
                                    <div class="form-group">
                                        <label class="form-label">权限级别</label>
                                        <select id="docPermission" class="form-control" required>
                                            <option value="normal">普通</option>
                                            <option value="confidential">机密</option>
                                            <option value="top_secret" id="topSecretOption" style="display: none;">绝密</option>
                                            <option value="special" id="specialOption" style="display: none;">特殊</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="form-group">
                                    <label class="form-label">文档内容</label>
                                    <textarea id="docContent" class="form-control" rows="10" placeholder="请输入文档内容..." required></textarea>
                                </div>
                                <div class="form-group">
                                    <button type="submit" class="btn btn-primary">
                                        <i class="icon icon-add"></i> 上传文档
                                    </button>
                                </div>
                            </form>
                        </div>

                        <!-- 用户管理卡片 -->
                        <div id="userManagementCard" class="card">
                            <div class="card-title">
                                <i class="icon icon-user"></i> 用户管理
                            </div>
                            <div class="table-container">
                                <table id="usersTable">
                                    <thead>
                                        <tr>
                                            <th>用户名</th>
                                            <th>当前权限</th>
                                            <th>新权限</th>
                                            <th>操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- 用户列表将通过JS动态填充 -->
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- 审计日志卡片 -->
                        <div id="auditLogsCard" class="card">
                            <div class="card-title">
                                <i class="icon icon-audit"></i> 审计日志
                            </div>
                            <div class="table-container">
                                <table id="auditLogsTable">
                                    <thead>
                                        <tr>
                                            <th>时间</th>
                                            <th>用户名</th>
                                            <th>操作</th>
                                            <th>详情</th>
                                            <th>IP地址</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- 审计日志将通过JS动态填充 -->
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <!-- 系统统计卡片 -->
                        <div id="systemStatsCard" class="card">
                            <div class="card-title">
                                <i class="icon icon-data"></i> 系统统计信息
                            </div>
                            <div id="statsContent">
                                <!-- 统计信息将通过JS动态填充 -->
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 文档查看模态框 -->
            <div id="documentModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3 id="modalDocTitle">文档标题</h3>
                        <button class="close-btn" id="closeModalBtn">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div style="margin-bottom: 20px;">
                            <span id="modalDocPermission" class="permission-badge" style="margin-right: 10px;">权限</span>
                            <span id="modalDocInfo">创建时间：- | 创建者：-</span>
                        </div>
                        <pre id="modalDocContent" style="white-space: pre-wrap; font-family: inherit; background: #f8f9fa; padding: 20px; border-radius: 8px;"></pre>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" id="closeModalBtn2">关闭</button>
                    </div>
                </div>
            </div>

            <!-- 紧急升级模态框 -->
            <div id="upgradeModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>紧急权限升级</h3>
                        <button class="close-btn" id="closeUpgradeModalBtn">&times;</button>
                    </div>
                    <div class="modal-body">
                        <p style="margin-bottom: 20px;">请输入紧急升级密码以提升到最高权限：</p>
                        <div class="form-group">
                            <input type="password" id="emergencyPassword" class="form-control" placeholder="请输入紧急升级密码">
                        </div>
                        <div class="alert" id="upgradeAlert"></div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" id="closeUpgradeModalBtn2">取消</button>
                        <button class="btn btn-success" id="submitUpgradeBtn">确认升级</button>
                    </div>
                </div>
            </div>

            <!-- 删除确认模态框 -->
            <div id="deleteConfirmModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>确认删除</h3>
                        <button class="close-btn" onclick="closeDeleteModal()">&times;</button>
                    </div>
                    <div class="modal-body">
                        <p id="deleteMessage"></p>
                        <div class="alert" id="deleteAlert"></div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" onclick="closeDeleteModal()">取消</button>
                        <button class="btn btn-danger" id="confirmDeleteBtn">确认删除</button>
                    </div>
                </div>
            </div>

            <!-- 统计数据模态框 -->
            <div id="statsModal" class="modal">
                <div class="modal-content">
                    <div class="modal-header">
                        <h3>系统统计信息</h3>
                        <button class="close-btn" id="closeStatsModalBtn">&times;</button>
                    </div>
                    <div class="modal-body">
                        <div id="statsModalContent">
                            <!-- 统计数据将通过JS动态填充 -->
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-primary" id="closeStatsModalBtn2">关闭</button>
                    </div>
                </div>
            </div>

            <script>
                // 全局变量
                let currentSession = null;
                let currentUser = null;
                const API_BASE = '/api';
                let documentToDelete = null;

                // DOM元素
                const loginPage = document.getElementById('loginPage');
                const mainPage = document.getElementById('mainPage');
                const loginForm = document.getElementById('loginForm');
                const loginAlert = document.getElementById('loginAlert');
                const logoutBtn = document.getElementById('logoutBtn');
                const emergencyUpgradeBtn = document.getElementById('emergencyUpgradeBtn');
                const statsBtn = document.getElementById('statsBtn');
                const backupBtn = document.getElementById('backupBtn');
                const currentUsername = document.getElementById('currentUsername');
                const currentPermission = document.getElementById('currentPermission');

                // 初始化
                document.addEventListener('DOMContentLoaded', function() {
                    // 检查是否已有会话
                    const savedSession = localStorage.getItem('document_session');
                    const savedUser = localStorage.getItem('document_user');
                    
                    if (savedSession && savedUser) {
                        try {
                            currentSession = savedSession;
                            currentUser = JSON.parse(savedUser);
                            showMainPage();
                        } catch (e) {
                            localStorage.clear();
                        }
                    }

                    // 登录表单提交
                    loginForm.addEventListener('submit', handleLogin);

                    // 退出登录
                    logoutBtn.addEventListener('click', handleLogout);

                    // 紧急升级按钮
                    emergencyUpgradeBtn.addEventListener('click', showUpgradeModal);

                    // 统计按钮
                    statsBtn.addEventListener('click', showStatsModal);

                    // 备份按钮
                    backupBtn.addEventListener('click', handleBackup);

                    // 导航菜单
                    document.querySelectorAll('.nav-item').forEach(item => {
                        item.addEventListener('click', function() {
                            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
                            document.querySelectorAll('.card').forEach(c => c.classList.remove('active'));
                            
                            this.classList.add('active');
                            document.getElementById(this.dataset.target + 'Card').classList.add('active');
                            
                            // 如果是统计页面，加载统计数据
                            if (this.dataset.target === 'systemStats') {
                                loadSystemStats();
                            }
                        });
                    });

                    // 模态框关闭
                    document.getElementById('closeModalBtn').addEventListener('click', hideDocumentModal);
                    document.getElementById('closeModalBtn2').addEventListener('click', hideDocumentModal);
                    document.getElementById('closeUpgradeModalBtn').addEventListener('click', hideUpgradeModal);
                    document.getElementById('closeUpgradeModalBtn2').addEventListener('click', hideUpgradeModal);
                    document.getElementById('submitUpgradeBtn').addEventListener('click', handleEmergencyUpgrade);
                    document.getElementById('closeStatsModalBtn').addEventListener('click', hideStatsModal);
                    document.getElementById('closeStatsModalBtn2').addEventListener('click', hideStatsModal);

                    // 添加文档表单
                    document.getElementById('addDocumentForm').addEventListener('submit', handleAddDocument);

                    // 删除确认按钮
                    document.getElementById('confirmDeleteBtn').addEventListener('click', function() {
                        if (documentToDelete) {
                            deleteDocument(documentToDelete.id);
                            closeDeleteModal();
                        }
                    });
                });

                // 显示登录页面
                function showLoginPage() {
                    loginPage.style.display = 'flex';
                    mainPage.style.display = 'none';
                    loginAlert.style.display = 'none';
                    loginForm.reset();
                }

                // 显示主页面
                function showMainPage() {
                    loginPage.style.display = 'none';
                    mainPage.style.display = 'block';
                    
                    // 更新用户信息
                    currentUsername.textContent = currentUser.username;
                    currentPermission.textContent = getPermissionText(currentUser.permission);
                    currentPermission.className = `permission-badge permission-${currentUser.permission}`;
                    
                    // 显示/隐藏功能按钮
                    if (currentUser.can_upgrade) {
                        emergencyUpgradeBtn.style.display = 'inline-flex';
                    }
                    
                    // 显示/隐藏导航项
                    const canAddDoc = ['special', 'top_secret'].includes(currentUser.permission);
                    document.getElementById('addDocumentNav').style.display = canAddDoc ? 'block' : 'none';
                    
                    const canManageUsers = currentUser.can_upgrade;
                    document.getElementById('userManagementNav').style.display = canManageUsers ? 'block' : 'none';
                    
                    const canViewAudit = ['special', 'top_secret'].includes(currentUser.permission);
                    document.getElementById('auditLogsNav').style.display = canViewAudit ? 'block' : 'none';
                    
                    // 系统统计对所有用户开放
                    document.getElementById('systemStatsNav').style.display = 'block';
                    
                    // 备份按钮只对特殊用户显示
                    if (currentUser.permission === 'special') {
                        backupBtn.style.display = 'inline-flex';
                    }
                    
                    // 权限选项控制
                    if (currentUser.permission === 'special') {
                        document.getElementById('topSecretOption').style.display = 'block';
                        document.getElementById('specialOption').style.display = 'block';
                    } else if (currentUser.permission === 'top_secret') {
                        document.getElementById('topSecretOption').style.display = 'none';
                        document.getElementById('specialOption').style.display = 'none';
                    }
                    
                    // 加载初始数据
                    loadDocuments();
                    if (canManageUsers) loadUsers();
                    if (canViewAudit) loadAuditLogs();
                }

                // 处理登录
                async function handleLogin(e) {
                    e.preventDefault();
                    
                    const username = document.getElementById('username').value.trim();
                    const password = document.getElementById('password').value.trim();
                    
                    if (!username || !password) {
                        showAlert('请输入用户名和密码', 'error');
                        return;
                    }

                    try {
                        const response = await fetch(`${API_BASE}/login`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ username, password })
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            currentSession = data.session_id;
                            currentUser = data.user;
                            
                            // 保存到本地存储
                            localStorage.setItem('document_session', currentSession);
                            localStorage.setItem('document_user', JSON.stringify(currentUser));
                            
                            showMainPage();
                        } else {
                            showAlert(data.error || '登录失败', 'error');
                        }
                    } catch (error) {
                        showAlert('网络错误，请检查服务器是否运行', 'error');
                        console.error('登录错误:', error);
                    }
                }

                // 处理退出登录
                function handleLogout() {
                    localStorage.removeItem('document_session');
                    localStorage.removeItem('document_user');
                    currentSession = null;
                    currentUser = null;
                    showLoginPage();
                }

                // 加载文档列表
                async function loadDocuments() {
                    try {
                        const response = await fetch(`${API_BASE}/documents`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const documents = await response.json();
                            renderDocumentsTable(documents);
                            document.getElementById('docCount').textContent = `${documents.length}个文档`;
                        }
                    } catch (error) {
                        console.error('加载文档错误:', error);
                    }
                }

                // 渲染文档表格
                function renderDocumentsTable(documents) {
                    const tbody = document.querySelector('#documentsTable tbody');
                    tbody.innerHTML = '';
                    
                    documents.forEach(doc => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td><strong>${doc.filename}</strong></td>
                            <td><span class="permission-badge permission-${doc.permission}">${doc.permission_text}</span></td>
                            <td>${doc.created_at}</td>
                            <td>${doc.created_by}</td>
                            <td style="white-space: nowrap;">
                                <button class="btn btn-primary btn-sm" onclick="viewDocument('${doc.id}')">查看</button>
                                <button class="btn btn-danger btn-sm" onclick="confirmDeleteDocument('${doc.id}', '${doc.filename}', '${doc.created_by}')">
                                    <i class="icon icon-delete"></i> 删除
                                </button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                }

                // 查看文档详情
                async function viewDocument(documentId) {
                    try {
                        const response = await fetch(`${API_BASE}/documents/${documentId}`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const doc = await response.json();
                            showDocumentModal(doc);
                        } else {
                            const data = await response.json();
                            showAlert(data.error || '无法查看文档', 'error');
                        }
                    } catch (error) {
                        console.error('查看文档错误:', error);
                    }
                }

                // 显示文档模态框
                function showDocumentModal(doc) {
                    document.getElementById('modalDocTitle').textContent = doc.filename;
                    document.getElementById('modalDocPermission').textContent = getPermissionText(doc.permission);
                    document.getElementById('modalDocPermission').className = `permission-badge permission-${doc.permission}`;
                    document.getElementById('modalDocInfo').textContent = `创建时间：${doc.created_at} | 创建者：${doc.created_by}`;
                    document.getElementById('modalDocContent').textContent = doc.content;
                    document.getElementById('documentModal').style.display = 'flex';
                }

                // 隐藏文档模态框
                function hideDocumentModal() {
                    document.getElementById('documentModal').style.display = 'none';
                }

                // 确认删除文档
                function confirmDeleteDocument(docId, filename, createdBy) {
                    documentToDelete = { id: docId, filename, createdBy };
                    const currentUsername = document.getElementById('currentUsername').textContent;
                    
                    let message = `确定要删除文档 <strong>"${filename}"</strong> 吗？<br><br>`;
                    message += `创建者：${createdBy}<br>`;
                    
                    if (currentUsername !== createdBy) {
                        message += `<br><span style="color: #dc3545;">⚠️ 注意：这不是您创建的文档！</span>`;
                    }
                    
                    document.getElementById('deleteMessage').innerHTML = message;
                    document.getElementById('deleteAlert').style.display = 'none';
                    document.getElementById('deleteConfirmModal').style.display = 'flex';
                }

                // 关闭删除确认模态框
                function closeDeleteModal() {
                    document.getElementById('deleteConfirmModal').style.display = 'none';
                    documentToDelete = null;
                }

                // 执行删除操作
                async function deleteDocument(documentId) {
                    try {
                        const response = await fetch(`${API_BASE}/documents/${documentId}`, {
                            method: 'DELETE',
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            showAlert('文档删除成功！', 'success');
                            loadDocuments(); // 重新加载文档列表
                        } else {
                            showAlert(data.error || '删除失败', 'error');
                        }
                    } catch (error) {
                        showAlert('网络错误，请稍后重试', 'error');
                        console.error('删除文档错误:', error);
                    }
                }

                // 处理添加文档
                async function handleAddDocument(e) {
                    e.preventDefault();
                    
                    const filename = document.getElementById('docFilename').value.trim();
                    const permission = document.getElementById('docPermission').value;
                    const content = document.getElementById('docContent').value.trim();
                    
                    if (!filename || !content) {
                        showAlert('请填写完整的文档信息', 'error');
                        return;
                    }

                    try {
                        const response = await fetch(`${API_BASE}/documents`, {
                            method: 'POST',
                            headers: {
                                'Authorization': currentSession,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                filename,
                                permission,
                                content
                            })
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            showAlert('文档上传成功！', 'success');
                            document.getElementById('addDocumentForm').reset();
                            loadDocuments();
                            
                            // 切换到文档列表
                            document.querySelector('.nav-item[data-target="documents"]').click();
                        } else {
                            showAlert(data.error || '上传失败', 'error');
                        }
                    } catch (error) {
                        showAlert('网络错误，请稍后重试', 'error');
                        console.error('上传文档错误:', error);
                    }
                }

                // 加载用户列表
                async function loadUsers() {
                    try {
                        const response = await fetch(`${API_BASE}/users`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const users = await response.json();
                            renderUsersTable(users);
                        }
                    } catch (error) {
                        console.error('加载用户错误:', error);
                    }
                }

                // 渲染用户表格
                function renderUsersTable(users) {
                    const tbody = document.querySelector('#usersTable tbody');
                    tbody.innerHTML = '';
                    
                    users.forEach(user => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${user.username}</td>
                            <td><span class="permission-badge permission-${user.permission}">${user.permission_text}</span></td>
                            <td>
                                <select class="form-control user-permission-select" data-user-id="${user.id}">
                                    <option value="normal" ${user.permission === 'normal' ? 'selected' : ''}>普通</option>
                                    <option value="confidential" ${user.permission === 'confidential' ? 'selected' : ''}>机密</option>
                                    <option value="top_secret" ${user.permission === 'top_secret' ? 'selected' : ''}>绝密</option>
                                    <option value="special" ${user.permission === 'special' ? 'selected' : ''}>特殊</option>
                                </select>
                            </td>
                            <td>
                                <button class="btn btn-primary btn-sm" onclick="updateUserPermission('${user.id}', this)">更新</button>
                            </td>
                        `;
                        tbody.appendChild(row);
                    });
                }

                // 更新用户权限
                async function updateUserPermission(userId, button) {
                    const select = document.querySelector(`select[data-user-id="${userId}"]`);
                    const newPermission = select.value;
                    
                    try {
                        const response = await fetch(`${API_BASE}/users/${userId}/permission`, {
                            method: 'PUT',
                            headers: {
                                'Authorization': currentSession,
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({ permission: newPermission })
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            showAlert('用户权限更新成功！', 'success');
                            loadUsers();
                            
                            // 如果更新的是当前用户自己，刷新页面
                            if (currentUser.id === userId) {
                                currentUser = data;
                                localStorage.setItem('document_user', JSON.stringify(currentUser));
                                showMainPage();
                            }
                        } else {
                            showAlert(data.error || '更新失败', 'error');
                        }
                    } catch (error) {
                        showAlert('网络错误，请稍后重试', 'error');
                        console.error('更新权限错误:', error);
                    }
                }

                // 加载审计日志
                async function loadAuditLogs() {
                    try {
                        const response = await fetch(`${API_BASE}/audit-logs`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const logs = await response.json();
                            renderAuditLogsTable(logs.reverse()); // 最新的在前面
                        }
                    } catch (error) {
                        console.error('加载审计日志错误:', error);
                    }
                }

                // 渲染审计日志表格
                function renderAuditLogsTable(logs) {
                    const tbody = document.querySelector('#auditLogsTable tbody');
                    tbody.innerHTML = '';
                    
                    logs.forEach(log => {
                        const date = new Date(log.timestamp);
                        const timeStr = date.toLocaleString('zh-CN');
                        
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${timeStr}</td>
                            <td>${log.username}</td>
                            <td>${log.action}</td>
                            <td>${log.details}</td>
                            <td>${log.ip || 'N/A'}</td>
                        `;
                        tbody.appendChild(row);
                    });
                }

                // 加载系统统计数据
                async function loadSystemStats() {
                    try {
                        const response = await fetch(`${API_BASE}/stats`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const stats = await response.json();
                            renderSystemStats(stats);
                        }
                    } catch (error) {
                        console.error('加载系统统计错误:', error);
                    }
                }

                // 渲染系统统计信息
                function renderSystemStats(stats) {
                    const statsContent = document.getElementById('statsContent');
                    
                    const userStats = stats.user_stats;
                    const docStats = stats.document_stats;
                    const dataFiles = stats.data_files;
                    
                    let html = `
                        <div class="stats-container">
                            <div class="stat-card">
                                <div class="stat-value stat-user">${userStats.total}</div>
                                <div class="stat-label">总用户数</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value stat-doc">${docStats.total}</div>
                                <div class="stat-label">总文档数</div>
                            </div>
                            <div class="stat-card">
                                <div class="stat-value stat-audit">${stats.audit_logs}</div>
                                <div class="stat-label">审计日志数</div>
                            </div>
                        </div>

                        <h3 style="margin: 30px 0 15px 0;">用户权限分布</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>权限级别</th>
                                        <th>用户数量</th>
                                        <th>占比</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="permission-badge permission-special">特殊</span></td>
                                        <td>${userStats.by_permission.special}</td>
                                        <td>${((userStats.by_permission.special / userStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-top-secret">绝密</span></td>
                                        <td>${userStats.by_permission.top_secret}</td>
                                        <td>${((userStats.by_permission.top_secret / userStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-confidential">机密</span></td>
                                        <td>${userStats.by_permission.confidential}</td>
                                        <td>${((userStats.by_permission.confidential / userStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-normal">普通</span></td>
                                        <td>${userStats.by_permission.normal}</td>
                                        <td>${((userStats.by_permission.normal / userStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <h3 style="margin: 30px 0 15px 0;">文档权限分布</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>权限级别</th>
                                        <th>文档数量</th>
                                        <th>占比</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td><span class="permission-badge permission-special">特殊</span></td>
                                        <td>${docStats.by_permission.special}</td>
                                        <td>${((docStats.by_permission.special / docStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-top-secret">绝密</span></td>
                                        <td>${docStats.by_permission.top_secret}</td>
                                        <td>${((docStats.by_permission.top_secret / docStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-confidential">机密</span></td>
                                        <td>${docStats.by_permission.confidential}</td>
                                        <td>${((docStats.by_permission.confidential / docStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                    <tr>
                                        <td><span class="permission-badge permission-normal">普通</span></td>
                                        <td>${docStats.by_permission.normal}</td>
                                        <td>${((docStats.by_permission.normal / docStats.total) * 100).toFixed(1)}%</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <h3 style="margin: 30px 0 15px 0;">数据文件信息</h3>
                        <div class="table-container">
                            <table>
                                <thead>
                                    <tr>
                                        <th>数据文件</th>
                                        <th>文件大小</th>
                                        <th>说明</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr>
                                        <td>users.json</td>
                                        <td>${formatFileSize(dataFiles.users)}</td>
                                        <td>用户数据文件</td>
                                    </tr>
                                    <tr>
                                        <td>documents.json</td>
                                        <td>${formatFileSize(dataFiles.documents)}</td>
                                        <td>文档数据文件</td>
                                    </tr>
                                    <tr>
                                        <td>audit_logs.json</td>
                                        <td>${formatFileSize(dataFiles.audit_logs)}</td>
                                        <td>审计日志文件</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>

                        <div style="margin-top: 30px; padding: 15px; background: #e7f3ff; border-radius: 10px;">
                            <h4>📊 系统说明</h4>
                            <p>• 所有数据自动保存到 <strong>data/</strong> 目录</p>
                            <p>• 服务器重启后数据不会丢失</p>
                            <p>• 审计日志自动记录所有操作</p>
                            <p>• 数据文件格式：JSON (易于备份和恢复)</p>
                        </div>
                    `;
                    
                    statsContent.innerHTML = html;
                }

                // 显示统计模态框
                async function showStatsModal() {
                    try {
                        const response = await fetch(`${API_BASE}/stats`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        if (response.ok) {
                            const stats = await response.json();
                            const modalContent = document.getElementById('statsModalContent');
                            
                            modalContent.innerHTML = `
                                <div style="text-align: center; margin-bottom: 20px;">
                                    <div style="display: inline-block; background: #007bff; color: white; padding: 10px 20px; border-radius: 20px; font-weight: bold;">
                                        系统统计概览
                                    </div>
                                </div>
                                
                                <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-bottom: 20px;">
                                    <div style="text-align: center;">
                                        <div style="font-size: 24px; font-weight: bold; color: #007bff;">${stats.user_stats.total}</div>
                                        <div style="color: #666; font-size: 14px;">总用户数</div>
                                    </div>
                                    <div style="text-align: center;">
                                        <div style="font-size: 24px; font-weight: bold; color: #28a745;">${stats.document_stats.total}</div>
                                        <div style="color: #666; font-size: 14px;">总文档数</div>
                                    </div>
                                    <div style="text-align: center;">
                                        <div style="font-size: 24px; font-weight: bold; color: #ffc107;">${stats.audit_logs}</div>
                                        <div style="color: #666; font-size: 14px;">审计日志</div>
                                    </div>
                                </div>
                                
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin-bottom: 15px;">
                                    <strong>用户分布:</strong>
                                    <div style="margin-top: 10px;">
                                        <span class="permission-badge permission-special" style="margin-right: 10px;">特殊: ${stats.user_stats.by_permission.special}</span>
                                        <span class="permission-badge permission-top-secret" style="margin-right: 10px;">绝密: ${stats.user_stats.by_permission.top_secret}</span>
                                        <span class="permission-badge permission-confidential" style="margin-right: 10px;">机密: ${stats.user_stats.by_permission.confidential}</span>
                                        <span class="permission-badge permission-normal">普通: ${stats.user_stats.by_permission.normal}</span>
                                    </div>
                                </div>
                                
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px; margin-bottom: 15px;">
                                    <strong>文档分布:</strong>
                                    <div style="margin-top: 10px;">
                                        <span class="permission-badge permission-special" style="margin-right: 10px;">特殊: ${stats.document_stats.by_permission.special}</span>
                                        <span class="permission-badge permission-top-secret" style="margin-right: 10px;">绝密: ${stats.document_stats.by_permission.top_secret}</span>
                                        <span class="permission-badge permission-confidential" style="margin-right: 10px;">机密: ${stats.document_stats.by_permission.confidential}</span>
                                        <span class="permission-badge permission-normal">普通: ${stats.document_stats.by_permission.normal}</span>
                                    </div>
                                </div>
                                
                                <div style="background: #f8f9fa; padding: 15px; border-radius: 10px;">
                                    <strong>数据文件大小:</strong>
                                    <div style="margin-top: 10px; font-size: 14px;">
                                        <div>📄 users.json: ${formatFileSize(stats.data_files.users)}</div>
                                        <div>📄 documents.json: ${formatFileSize(stats.data_files.documents)}</div>
                                        <div>📄 audit_logs.json: ${formatFileSize(stats.data_files.audit_logs)}</div>
                                    </div>
                                </div>
                            `;
                            
                            document.getElementById('statsModal').style.display = 'flex';
                        }
                    } catch (error) {
                        console.error('加载统计信息错误:', error);
                    }
                }

                // 隐藏统计模态框
                function hideStatsModal() {
                    document.getElementById('statsModal').style.display = 'none';
                }

                // 处理数据备份
                async function handleBackup() {
                    if (!confirm('确定要创建数据备份吗？')) {
                        return;
                    }
                    
                    try {
                        const response = await fetch(`${API_BASE}/backup`, {
                            headers: {
                                'Authorization': currentSession
                            }
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            showAlert(`数据备份成功！备份文件: ${data.backup_file}`, 'success');
                        } else {
                            showAlert(data.error || '备份失败', 'error');
                        }
                    } catch (error) {
                        showAlert('网络错误，请稍后重试', 'error');
                        console.error('数据备份错误:', error);
                    }
                }

                // 显示紧急升级模态框
                function showUpgradeModal() {
                    document.getElementById('upgradeAlert').style.display = 'none';
                    document.getElementById('emergencyPassword').value = '';
                    document.getElementById('upgradeModal').style.display = 'flex';
                }

                // 隐藏紧急升级模态框
                function hideUpgradeModal() {
                    document.getElementById('upgradeModal').style.display = 'none';
                }

                // 处理紧急升级
                async function handleEmergencyUpgrade() {
                    const password = document.getElementById('emergencyPassword').value.trim();
                    
                    if (!password) {
                        showAlertInModal('请输入紧急升级密码', 'error');
                        return;
                    }

                    try {
                        const response = await fetch(`${API_BASE}/emergency-upgrade`, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json'
                            },
                            body: JSON.stringify({
                                session_id: currentSession,
                                emergency_password: password
                            })
                        });

                        const data = await response.json();
                        
                        if (response.ok) {
                            showAlertInModal('紧急升级成功！您现在拥有特殊权限。', 'success');
                            
                            // 更新当前用户信息
                            currentUser = data.user;
                            localStorage.setItem('document_user', JSON.stringify(currentUser));
                            
                            setTimeout(() => {
                                hideUpgradeModal();
                                showMainPage();
                            }, 1500);
                        } else {
                            showAlertInModal(data.error || '升级失败', 'error');
                        }
                    } catch (error) {
                        showAlertInModal('网络错误，请稍后重试', 'error');
                        console.error('紧急升级错误:', error);
                    }
                }

                // 工具函数
                function getPermissionText(permission) {
                    const map = {
                        'special': '特殊',
                        'top_secret': '绝密',
                        'confidential': '机密',
                        'normal': '普通'
                    };
                    return map[permission] || permission;
                }

                function formatFileSize(bytes) {
                    if (bytes === 0) return '0 B';
                    const k = 1024;
                    const sizes = ['B', 'KB', 'MB', 'GB'];
                    const i = Math.floor(Math.log(bytes) / Math.log(k));
                    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }

                function showAlert(message, type) {
                    // 创建或获取提示框
                    let alertDiv = document.querySelector('.main-content .alert-temp');
                    if (!alertDiv) {
                        alertDiv = document.createElement('div');
                        alertDiv.className = `alert alert-${type} alert-temp`;
                        alertDiv.style.cssText = `
                            position: fixed;
                            top: 20px;
                            right: 20px;
                            z-index: 9999;
                            padding: 15px 25px;
                            border-radius: 10px;
                            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
                            animation: slideIn 0.3s ease-out;
                        `;
                        document.body.appendChild(alertDiv);
                        
                        // 添加CSS动画
                        const style = document.createElement('style');
                        style.textContent = `
                            @keyframes slideIn {
                                from { transform: translateX(100%); opacity: 0; }
                                to { transform: translateX(0); opacity: 1; }
                            }
                            .alert-success {
                                background: #d4edda;
                                color: #155724;
                                border: 1px solid #c3e6cb;
                            }
                            .alert-error {
                                background: #f8d7da;
                                color: #721c24;
                                border: 1px solid #f5c6cb;
                            }
                            .alert-info {
                                background: #d1ecf1;
                                color: #0c5460;
                                border: 1px solid #bee5eb;
                            }
                        `;
                        if (!document.querySelector('#alert-styles')) {
                            style.id = 'alert-styles';
                            document.head.appendChild(style);
                        }
                    }
                    
                    alertDiv.textContent = message;
                    alertDiv.className = `alert alert-${type} alert-temp`;
                    alertDiv.style.display = 'block';
                    
                    // 自动隐藏
                    setTimeout(() => {
                        alertDiv.style.animation = 'slideOut 0.3s ease-out';
                        setTimeout(() => {
                            if (alertDiv.parentNode) {
                                document.body.removeChild(alertDiv);
                            }
                        }, 300);
                    }, 3000);
                }

                function showAlertInModal(message, type) {
                    const alertDiv = document.getElementById('upgradeAlert');
                    alertDiv.textContent = message;
                    alertDiv.className = `alert alert-${type}`;
                    alertDiv.style.display = 'block';
                }

                // 全局导出函数
                window.viewDocument = viewDocument;
                window.updateUserPermission = updateUserPermission;
                window.confirmDeleteDocument = confirmDeleteDocument;
                window.closeDeleteModal = closeDeleteModal;
            </script>
        </body>
        </html>
        """
    except:
        # 如果前端文件不存在，返回简单的信息页面
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>安全文档库管理系统</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
                .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 10px; }
                h1 { color: #333; text-align: center; }
                .info { background: #e7f3ff; padding: 15px; border-radius: 5px; margin: 20px 0; }
                .endpoints { background: #f0f0f0; padding: 15px; border-radius: 5px; }
                .permission-levels { display: flex; justify-content: space-between; margin: 20px 0; }
                .level { text-align: center; padding: 10px; border-radius: 5px; flex: 1; margin: 0 5px; }
                .special { background: #8e44ad; color: white; }
                .top-secret { background: #c0392b; color: white; }
                .confidential { background: #f39c12; color: white; }
                .normal { background: #27ae60; color: white; }
                .api-list { background: #f9f9f9; padding: 15px; border-radius: 5px; margin: 10px 0; }
                .api-list code { background: #e0e0e0; padding: 2px 5px; border-radius: 3px; }
                .data-info { background: #d4edda; padding: 15px; border-radius: 5px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>安全文档库管理系统 v3.1</h1>
                <div class="data-info">
                    <h3>✅ 数据持久化已启用</h3>
                    <p>数据已保存到 <strong>data/</strong> 目录</p>
                    <p>服务器重启后数据不会丢失</p>
                </div>
                
                <div class="info">
                    <p>服务器运行在: <strong>localhost:5000</strong></p>
                    <p>数据目录: <strong>data/</strong> (包含 users.json, documents.json, audit_logs.json)</p>
                    <p>✅ 后端API服务正常运行中</p>
                </div>
                
                <div class="permission-levels">
                    <div class="level special">
                        <h3>特殊权限</h3>
                        <p>2个用户</p>
                        <p>最高访问级别</p>
                    </div>
                    <div class="level top-secret">
                        <h3>绝密权限</h3>
                        <p>3个用户</p>
                        <p>高级访问权限</p>
                    </div>
                    <div class="level confidential">
                        <h3>机密权限</h3>
                        <p>12个用户</p>
                        <p>中级访问权限</p>
                    </div>
                    <div class="level normal">
                        <h3>普通权限</h3>
                        <p>9个用户</p>
                        <p>基础访问权限</p>
                    </div>
                </div>
                
                <h3>可用API端点:</h3>
                <div class="api-list">
                    <p><strong>健康检查:</strong> <code>GET /api/health</code></p>
                    <p><strong>用户登录:</strong> <code>POST /api/login</code></p>
                    <p><strong>获取文档列表:</strong> <code>GET /api/documents</code></p>
                    <p><strong>查看文档内容:</strong> <code>GET /api/documents/&lt;id&gt;</code></p>
                    <p><strong>删除文档:</strong> <code>DELETE /api/documents/&lt;id&gt;</code></p>
                    <p><strong>添加文档:</strong> <code>POST /api/documents</code></p>
                    <p><strong>获取用户列表:</strong> <code>GET /api/users</code></p>
                    <p><strong>更新用户权限:</strong> <code>PUT /api/users/&lt;id&gt;/permission</code></p>
                    <p><strong>修改密码:</strong> <code>POST /api/change-password</code></p>
                    <p><strong>紧急权限升级:</strong> <code>POST /api/emergency-upgrade</code></p>
                    <p><strong>审计日志:</strong> <code>GET /api/audit-logs</code></p>
                    <p><strong>系统统计:</strong> <code>GET /api/stats</code></p>
                    <p><strong>数据备份:</strong> <code>GET /api/backup</code> (特殊权限)</p>
                </div>
                
                <div style="margin-top: 20px; padding: 15px; background: #fff3cd; border-radius: 5px;">
                    <h3>测试账户:</h3>
                    <p><strong>特殊用户:</strong> special_user1 / special_password1</p>
                    <p><strong>绝密用户:</strong> ts_user1 / ts_password1</p>
                    <p><strong>机密用户:</strong> c_user1 / c_password1</p>
                    <p><strong>普通用户:</strong> normal_user1 / normal_password1</p>
                    <p><strong>紧急升级密码:</strong> hello</p>
                </div>
                
                <div style="margin-top: 20px; color: #666; font-size: 14px;">
                    <p>当前版本包含功能：登录认证、权限管理、文档CRUD、用户管理、审计日志、紧急升级、数据持久化</p>
                    <p>数据保存位置: data/users.json, data/documents.json, data/audit_logs.json</p>
                </div>
            </div>
        </body>
        </html>
        """

# ==================== 启动应用 ====================

if __name__ == '__main__':
    print("=" * 60)
    print("安全文档库系统 v3.1 (数据持久化版) 启动中...")
    print("=" * 60)
    print(f"📍 本地访问: http://localhost:5000")
    print(f"📁 数据目录: {DATA_DIR}/")
    print(f"📊 用户数据: {len(users)} 个用户")
    print(f"📄 文档数据: {len(documents)} 个文档") 
    print(f"📋 审计日志: {len(audit_logs)} 条记录")
    print("=" * 60)
    print("权限等级 (从高到低):")
    print("🔮 特殊权限: 2个用户 (最高权限)")
    print("🔴 绝密权限: 3个用户") 
    print("🟡 机密权限: 12个用户")
    print("🟢 普通权限: 9个用户")
    print("=" * 60)
    print("数据持久化:")
    print("✓ 用户数据自动保存到 users.json")
    print("✓ 文档数据自动保存到 documents.json")
    print("✓ 审计日志自动保存到 audit_logs.json")
    print("✓ 服务器重启后数据不会丢失")
    print("=" * 60)
    print("API功能:")
    print("✓ 用户登录认证")
    print("✓ 文档增删改查 (持久化)")
    print("✓ 用户权限管理 (持久化)")
    print("✓ 审计日志记录 (持久化)")
    print("✓ 紧急权限升级 (持久化)")
    print("✓ 密码修改功能 (持久化)")
    print("✓ 数据备份功能")
    print("✓ 系统统计信息")
    print("=" * 60)
    print("启动完成，等待请求...")
    print("=" * 60)
    
    # 监听所有接口
    app.run(host='0.0.0.0', port=5000, debug=False)
