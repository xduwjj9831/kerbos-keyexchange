"""
================================================================================
 Kerberos 密钥分配协议 (Kerberos Key Distribution Protocol) 模拟实现
================================================================================
 
 Kerberos 是一种基于对称密钥的身份认证协议，由 MIT 开发，广泛应用于
 Windows Active Directory、Hadoop 等系统中。
 
 核心角色：
 ┌─────────────────────────────────────────────────────────────┐
 │  KDC (Key Distribution Center)   —— 密钥分发中心            │
 │    ├── AS (Authentication Service) —— 认证服务              │
 │    └── TGS (Ticket Granting Service) —— 票据授权服务        │
 │  Client  —— 客户端（用户）                                  │
 │  Server  —— 目标服务端（如文件服务器、打印服务等）           │
 └─────────────────────────────────────────────────────────────┘
 
 协议流程（6步）：
 ┌─────────────────────────────────────────────────────────────────────┐
 │  1. Client ──→ AS : "我是 Alice，我想访问服务"                       │
 │  2. AS ──→ Client : {K_c_tgs}K_c  +  TGT = {K_c_tgs, Alice}K_tgs │
 │                    （用客户端密码加密的会话密钥 + 票据授权票据）       │
 │  3. Client ──→ TGS : TGT + Authenticator = {Alice, 时间戳}K_c_tgs │
 │  4. TGS ──→ Client : {K_c_s}K_c_tgs  +  Service Ticket           │
 │                    （用会话密钥加密的服务密钥 + 服务票据）            │
 │  5. Client ──→ Server : Service Ticket + Authenticator            │
 │  6. Server ──→ Client : {时间戳+1}K_c_s（可选，双向认证）           │
 └─────────────────────────────────────────────────────────────────────┘

 本代码使用 cryptography 库的 Fernet 对称加密来模拟 Kerberos 的核心流程。
================================================================================
"""

import os
import time
import base64
import sys
import io
from cryptography.fernet import Fernet


# ------------------------------------------------------------------
#  Windows GBK terminal encoding compatibility: replace instead of crash
# ------------------------------------------------------------------
if sys.stdout.encoding and sys.stdout.encoding.upper() not in ('UTF-8', 'UTF8'):
    sys.stdout = io.TextIOWrapper(
        sys.stdout.buffer, encoding='utf-8', errors='replace'
    )



from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# ============================================================================
#  工具函数
# ============================================================================

def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    从密码派生出一个对称密钥（模拟 Kerberos 中用户密码派生的长期密钥）。
    
    参数:
        password: 用户的密码字符串
        salt:     加密盐值，增加破解难度
    
    返回:
        一个经过 base64 编码的 Fernet 密钥（32字节）
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key_bytes = kdf.derive(password.encode())
    # Fernet 要求密钥是 base64 编码的 32 字节数据
    return base64.urlsafe_b64encode(key_bytes)


def generate_fernet_key() -> bytes:
    """
    生成一个随机的 Fernet 对称密钥。
    这是真正安全的随机密钥，用于会话密钥的生成。
    """
    return Fernet.generate_key()


def encrypt_message(key: bytes, message: str) -> bytes:
    """
    使用 Fernet 对称加密对消息进行加密。
    
    参数:
        key:     base64 编码的 32 字节对称密钥
        message: 要加密的明文消息
    
    返回:
        加密后的密文（bytes 类型）
    """
    f = Fernet(key)
    return f.encrypt(message.encode())


def decrypt_message(key: bytes, ciphertext: bytes) -> str:
    """
    使用 Fernet 对称密钥解密密文。
    
    参数:
        key:        base64 编码的 32 字节对称密钥
        ciphertext: 要解密的密文
    
    返回:
        解密后的明文字符串
    """
    f = Fernet(key)
    return f.decrypt(ciphertext).decode()


# ============================================================================
#  核心数据结构 —— 票据（Ticket）
# ============================================================================

class Ticket:
    """
    Kerberos 票据（Ticket），这是协议中最核心的数据结构。
    
    票据由 KDC 签发，包含用户的身份信息和会话密钥，
    并使用目标服务（TGS 或目标 Server）的密钥加密，
    因此票据的接收者可以解密验证，而客户端无法篡改票据内容。
    """
    
    def __init__(self, client_id: str, server_id: str, session_key: bytes,
                 lifetime: int, timestamp: float):
        """
        参数:
            client_id:   客户端身份标识（如 "Alice"）
            server_id:   服务端身份标识（如 "TGS" 或 "FileServer"）
            session_key: 此票据中包含的会话密钥（用于后续通信）
            lifetime:    票据的有效期（秒）
            timestamp:   票据签发的时间戳
        """
        self.client_id = client_id
        self.server_id = server_id
        self.session_key = session_key
        self.lifetime = lifetime
        self.timestamp = timestamp

    def to_string(self) -> str:
        """
        将票据对象序列化为字符串，方便加密传输。
        """
        return (f"client={self.client_id}|server={self.server_id}|"
                f"session_key={base64.urlsafe_b64encode(self.session_key).decode()}|"
                f"lifetime={self.lifetime}|timestamp={self.timestamp}")

    @staticmethod
    def from_string(data: str) -> 'Ticket':
        """
        从字符串反序列化还原票据对象。
        """
        parts = dict(item.split("=", 1) for item in data.split("|"))
        return Ticket(
            client_id=parts["client"],
            server_id=parts["server"],
            session_key=base64.urlsafe_b64decode(parts["session_key"]),
            lifetime=int(parts["lifetime"]),
            timestamp=float(parts["timestamp"]),
        )

    def is_expired(self) -> bool:
        """
        检查票据是否已过期。
        """ 
        return time.time() > (self.timestamp + self.lifetime)


# ============================================================================
#  核心数据结构 —— 认证器（Authenticator）
# ============================================================================

class Authenticator:
    """
    认证器（Authenticator），用于证明客户端持有某个会话密钥。
    
    与票据不同，认证器由客户端自己生成，并使用会话密钥加密。
    认证器中包含客户端的 ID 和时间戳，用于向服务端证明
    客户端"当前时刻"仍然知晓会话密钥（防止重放攻击）。
    
    认证器是一次性使用的，每次请求都需要重新生成。
    """
    
    def __init__(self, client_id: str, timestamp: float):
        """
        参数:
            client_id: 客户端身份标识
            timestamp: 当前时间戳，服务端会检查时间差是否在允许范围内
        """
        self.client_id = client_id
        self.timestamp = timestamp

    def to_string(self) -> str:
        return f"client={self.client_id}|timestamp={self.timestamp}"


# ============================================================================
#  KDC —— 密钥分发中心（包含 AS + TGS）
# ============================================================================

class KDC:
    """
    KDC（Key Distribution Center）—— 密钥分发中心。
    
    Kerberos 的核心可信第三方，负责：
    1. 验证客户端的身份（AS 的职责）
    2. 颁发票据授权票据 TGT（AS 的职责）
    3. 验证 TGT 并颁发服务票据（TGS 的职责）
    
    Kerberos 的安全基础在于：KDC 是"可信的第三方"，
    所有参与方都信任 KDC 签发的票据。
    """
    
    def __init__(self):
        """
        初始化 KDC，包含：
        - 用户数据库（存储用户密码）
        - TGS 的长期密钥（用于加密 TGT）
        """
        # ----- 用户数据库：存储所有注册用户的密码 -----
        # 在真实 Kerberos 中，KDC 存储的是用户密码哈希后的长期密钥
        # 这里为了直观演示，直接存储密码字符串
        self.user_database = {
            "Alice":   "alice_password_123",
            "Bob":     "bob_password_456",
            "Charlie": "charlie_password_789",
        }

        # ----- 生成 TGS 的长期密钥 -----
        # TGS 是 KDC 的一部分，它的密钥只有 KDC 自己知道
        # 这个密钥用于加密 TGT（票据授权票据），确保客户端无法伪造 TGT
        self.tgs_key = generate_fernet_key()
        self.tgs_id = "TGS"

        # ----- 存储各个目标服务的长期密钥 -----
        # 每个目标服务（如文件服务器）都有一个预共享的长期密钥
        # 在真实环境中，这些密钥是管理员手动配置的
        self.service_keys = {}
        print("\n  [KDC 初始化完成]")
        print(f"  ├─ 已注册用户: {list(self.user_database.keys())}")
        print(f"  └─ TGS 长期密钥: {base64.urlsafe_b64encode(self.tgs_key).decode()[:16]}...\n")

    def register_service(self, service_id: str, service_key: bytes):
        """
        在 KDC 上注册一个目标服务，并存储它的长期密钥。
        
        参数:
            service_id:  服务标识（如 "FileServer", "PrintServer"）
            service_key: 该服务的长期密钥（预共享密钥）
        """
        self.service_keys[service_id] = service_key
        print(f"  [KDC] 服务 '{service_id}' 注册成功")

    # ------------------------------------------------------------------
    #  AS（Authentication Service）—— 认证服务
    #  职责：验证用户身份，颁发 TGT（票据授权票据）
    # ------------------------------------------------------------------

    def authenticate_user(self, client_id: str, client_password: str) -> dict:
        """
        第1步和第2步：AS 验证用户身份，返回会话密钥和 TGT。
        
        参数:
            client_id:       客户端声称的身份（如 "Alice"）
            client_password: 客户端提供的密码（用于验证身份）
        
        返回:
            包含以下内容的字典：
            - status:       "success" 或 "failed"
            - message:       提示信息
            - session_key:   用于客户端与 TGS 之间通信的会话密钥 K_c_tgs
            - encrypted_tgt: 用 TGS 密钥加密后的 TGT（客户端无法解密）
        
        流程说明:
        ┌────────────────────────────────────────────────────────────┐
        │  ① 客户端发送请求: "我是 {client_id}，请给我 TGT"           │
        │  ② AS 查找用户密码，验证身份                                │
        │  ③ 生成一个随机会话密钥 K_c_tgs                            │
        │  ④ 创建 TGT，包含 {client_id, K_c_tgs}，用 K_tgs 加密      │
        │  ⑤ 将 {K_c_tgs} 用客户端密码加密，连同加密的 TGT 一起返回   │
        │  ⑥ 客户端用自己的密码解密得到 K_c_tgs，但打不开 TGT          │
        └────────────────────────────────────────────────────────────┘
        """
        print(f"  [AS] 收到 '{client_id}' 的身份认证请求...")

        # ---- ① 验证用户身份 ----
        if client_id not in self.user_database:
            return {"status": "failed", "message": f"用户 '{client_id}' 不存在"}
        
        stored_password = self.user_database[client_id]
        if client_password != stored_password:
            return {"status": "failed", "message": "密码错误，认证失败"}

        print(f"  [AS] ✅ 用户 '{client_id}' 身份验证通过")

        # ---- ② 生成会话密钥 K_c_tgs ----
        # 这个会话密钥用于客户端与 TGS 之间的安全通信
        session_key_c_tgs = generate_fernet_key()
        print(f"  [AS] 🔑 生成会话密钥 K_c_tgs: "
              f"{base64.urlsafe_b64encode(session_key_c_tgs).decode()[:16]}...")

        # ---- ③ 创建 TGT（票据授权票据）----
        # TGT 包含：client_id, server_id=TGS, session_key, lifetime, timestamp
        # TGT 使用 TGS 的长期密钥 K_tgs 加密，客户端无法查看或篡改其内容
        tgt = Ticket(
            client_id=client_id,
            server_id=self.tgs_id,
            session_key=session_key_c_tgs,
            lifetime=3600,           # TGT 有效期 1 小时
            timestamp=time.time(),
        )
        encrypted_tgt = encrypt_message(self.tgs_key, tgt.to_string())
        print(f"  [AS] 🎫 生成 TGT（有效期: 3600 秒）")

        # ---- ④ 用客户端密码加密会话密钥 ----
        # 这样只有知道密码的客户端才能解密得到会话密钥
        salt = b"kerberos_salt"
        client_key = derive_key_from_password(client_password, salt)
        encrypted_session_key = encrypt_message(client_key,
                                                base64.urlsafe_b64encode(
                                                    session_key_c_tgs).decode())

        print(f"  [AS] 📦 将会话密钥用用户密码加密后返回\n")

        return {
            "status": "success",
            "message": f"用户 '{client_id}' 认证成功，已颁发 TGT",
            "encrypted_session_key": encrypted_session_key,
            "encrypted_tgt": encrypted_tgt,
        }

    # ------------------------------------------------------------------
    #  TGS（Ticket Granting Service）—— 票据授权服务
    #  职责：验证 TGT，颁发访问目标服务的 Service Ticket
    # ------------------------------------------------------------------

    def request_service_ticket(self, client_id: str, encrypted_tgt: bytes,
                               encrypted_authenticator: bytes,
                               target_service: str) -> dict:
        """
        第3步和第4步：TGS 验证 TGT 和认证器，颁发服务票据。
        
        参数:
            client_id:                客户端身份标识
            encrypted_tgt:            用 TGS 密钥加密的 TGT（来自第2步）
            encrypted_authenticator:  用会话密钥 K_c_tgs 加密的认证器
            target_service:           客户端要访问的目标服务（如 "FileServer"）
        
        返回:
            包含服务票据和会话密钥的字典
        
        流程说明:
        ┌────────────────────────────────────────────────────────────┐
        │  ① 客户端发送: TGT + Authenticator（用 K_c_tgs 加密）       │
        │  ② TGS 用 K_tgs 解密 TGT，提取 {client_id, K_c_tgs}       │
        │  ③ TGS 用 K_c_tgs 解密 Authenticator，验证客户端身份       │
        │  ④ 比对 TGT 中的 client_id 和 Authenticator 中的 client_id │
        │  ⑤ 验证通过后，生成新的会话密钥 K_c_s                     │
        │  ⑥ 创建 Service Ticket（用目标服务的密钥加密）              │
        │  ⑦ 将 K_c_s（用 K_c_tgs 加密）连同 Service Ticket 返回     │
        └────────────────────────────────────────────────────────────┘
        """
        print(f"  [TGS] 收到 '{client_id}' 对服务 '{target_service}' 的票据请求...")

        # ---- ① 解密 TGT，提取会话密钥 K_c_tgs ----
        try:
            tgt_str = decrypt_message(self.tgs_key, encrypted_tgt)
            tgt = Ticket.from_string(tgt_str)
        except Exception as e:
            return {"status": "failed", "message": f"TGT 解密失败: {e}"}

        # ---- ② 验证 TGT 有效性 ----
        if tgt.is_expired():
            return {"status": "failed", "message": "TGT 已过期，请重新认证"}

        if tgt.client_id != client_id:
            return {"status": "failed", "message": "TGT 中的客户端 ID 不匹配"}

        print(f"  [TGS] ✅ TGT 验证通过, 会话密钥 K_c_tgs 已提取")

        # ---- ③ 用会话密钥解密认证器 ----
        # 如果客户端不持有正确的 K_c_tgs，认证器就无法解密
        session_key_c_tgs = tgt.session_key
        try:
            auth_str = decrypt_message(session_key_c_tgs, encrypted_authenticator)
            auth_parts = dict(item.split("=") for item in auth_str.split("|"))
        except Exception as e:
            return {"status": "failed", "message": f"认证器解密失败: {e}"}

        # ---- ④ 验证认证器 ----
        if auth_parts["client"] != client_id:
            return {"status": "failed", "message": "认证器中的客户端 ID 不匹配"}

        # 检查时间戳（防止重放攻击）
        auth_time = float(auth_parts["timestamp"])
        if abs(time.time() - auth_time) > 300:  # 允许5分钟的时间偏差
            return {"status": "failed", "message": "认证器时间戳无效（可能为重放攻击）"}

        print(f"  [TGS] ✅ 认证器验证通过（时间偏差: {time.time() - auth_time:.1f} 秒）")

        # ---- ⑤ 检查目标服务是否已注册 ----
        if target_service not in self.service_keys:
            return {"status": "failed",
                    "message": f"目标服务 '{target_service}' 未注册"}

        # ---- ⑥ 生成新的会话密钥 K_c_s ----
        # 这个密钥用于客户端与目标服务之间的安全通信
        session_key_c_s = generate_fernet_key()
        print(f"  [TGS] 🔑 生成服务会话密钥 K_c_s: "
              f"{base64.urlsafe_b64encode(session_key_c_s).decode()[:16]}...")

        # ---- ⑦ 创建 Service Ticket（服务票据）----
        # 服务票据用目标服务的长期密钥加密，只有目标服务能解密
        service_ticket = Ticket(
            client_id=client_id,
            server_id=target_service,
            session_key=session_key_c_s,
            lifetime=600,            # 服务票据有效期较短（10分钟）
            timestamp=time.time(),
        )
        service_key = self.service_keys[target_service]
        encrypted_service_ticket = encrypt_message(
            service_key, service_ticket.to_string()
        )
        print(f"  [TGS] 🎫 生成 Service Ticket（有效期: 600 秒）")

        # ---- ⑧ 用 K_c_tgs 加密 K_c_s 返回给客户端 ----
        encrypted_service_session_key = encrypt_message(
            session_key_c_tgs,
            base64.urlsafe_b64encode(session_key_c_s).decode()
        )

        print(f"  [TGS] 📦 将服务会话密钥用 K_c_tgs 加密后返回\n")

        return {
            "status": "success",
            "message": f"服务票据已颁发，可访问 '{target_service}'",
            "encrypted_service_session_key": encrypted_service_session_key,
            "encrypted_service_ticket": encrypted_service_ticket,
        }


# ============================================================================
#  Client —— 客户端
# ============================================================================

class Client:
    """
    Kerberos 客户端，模拟用户的操作。
    
    客户端需要完成以下工作：
    1. 向 AS 发起认证请求，获取 TGT
    2. 向 TGS 请求服务票据
    3. 向目标服务发起访问请求
    """
    
    def __init__(self, client_id: str, password: str):
        """
        参数:
            client_id: 客户端身份标识
            password:  客户端的密码（用于向 AS 证明身份）
        """
        self.client_id = client_id
        self.password = password
        self.session_key_c_tgs = None   # 与 TGS 通信的会话密钥
        self.tgt = None                  # 票据授权票据
        self.session_key_c_s = None      # 与服务通信的会话密钥
        self.service_ticket = None       # 服务票据

    def request_tgt(self, kdc: KDC) -> bool:
        """
        第1步和第2步：向 AS 请求 TGT（票据授权票据）。
        
        流程：
        ① 客户端构造请求（实际上只是告诉 AS 自己是谁）
        ② AS 验证密码，返回加密的会话密钥和 TGT
        ③ 客户端用自己的密码解密得到会话密钥 K_c_tgs
        ④ 客户端保存 TGT 和 K_c_tgs
        
        注意：客户端无法解密 TGT，因为它用 TGS 的密钥加密了。
        """
        print(f"\n{'='*60}")
        print(f"  📍 第1-2步: {self.client_id} 向 AS 请求 TGT")
        print(f"{'='*60}")

        # 发送认证请求
        result = kdc.authenticate_user(self.client_id, self.password)

        if result["status"] == "failed":
            print(f"  ❌ 认证失败: {result['message']}")
            return False

        # 用密码解密得到会话密钥 K_c_tgs
        salt = b"kerberos_salt"
        client_key = derive_key_from_password(self.password, salt)
        session_key_b64 = decrypt_message(client_key,
                                          result["encrypted_session_key"])
        self.session_key_c_tgs = base64.urlsafe_b64decode(session_key_b64)

        # 保存 TGT（密文形式即可，客户端无法也不需要解密）
        self.tgt = result["encrypted_tgt"]

        print(f"  ✅ 获取 TGT 成功!")
        print(f"  🔑 会话密钥 K_c_tgs: "
              f"{base64.urlsafe_b64encode(self.session_key_c_tgs).decode()[:16]}...")
        print(f"  🎫 TGT（已加密，客户端无法查看内容）")
        return True

    def request_service_access(self, kdc: KDC, target_service: str) -> bool:
        """
        第3步和第4步：向 TGS 请求访问目标服务的服务票据。
        
        流程：
        ① 客户端生成认证器（Authenticator），用 K_c_tgs 加密
        ② 将 TGT + 加密的认证器 发送给 TGS
        ③ TGS 验证通过后，返回加密的服务会话密钥和服务票据
        ④ 客户端用 K_c_tgs 解密得到服务会话密钥 K_c_s
        ⑤ 客户端保存服务票据和 K_c_s
        """
        print(f"\n{'='*60}")
        print(f"  📍 第3-4步: {self.client_id} 向 TGS 请求访问 '{target_service}'")
        print(f"{'='*60}")

        # 生成认证器（Authenticator）
        # 认证器包含客户端 ID 和时间戳，用会话密钥 K_c_tgs 加密
        authenticator = Authenticator(
            client_id=self.client_id,
            timestamp=time.time(),
        )
        encrypted_authenticator = encrypt_message(
            self.session_key_c_tgs, authenticator.to_string()
        )

        # 向 TGS 发送请求
        result = kdc.request_service_ticket(
            client_id=self.client_id,
            encrypted_tgt=self.tgt,
            encrypted_authenticator=encrypted_authenticator,
            target_service=target_service,
        )

        if result["status"] == "failed":
            print(f"  ❌ 服务票据请求失败: {result['message']}")
            return False

        # 用 K_c_tgs 解密得到服务会话密钥 K_c_s
        session_key_b64 = decrypt_message(
            self.session_key_c_tgs,
            result["encrypted_service_session_key"]
        )
        self.session_key_c_s = base64.urlsafe_b64decode(session_key_b64)

        # 保存服务票据
        self.service_ticket = result["encrypted_service_ticket"]

        print(f"  ✅ 获取服务票据成功!")
        print(f"  🔑 服务会话密钥 K_c_s: "
              f"{base64.urlsafe_b64encode(self.session_key_c_s).decode()[:16]}...")
        print(f"  🎫 Service Ticket（已加密，客户端无法查看内容）")
        return True

    def access_service(self, server: 'TargetServer') -> str:
        """
        第5步和第6步：使用服务票据访问目标服务。
        
        流程：
        ① 客户端生成新的认证器，用 K_c_s 加密
        ② 将 Service Ticket + 加密的认证器 发送给目标服务
        ③ 目标服务解密验证后，返回响应数据
        """
        print(f"\n{'='*60}")
        print(f"  📍 第5步: {self.client_id} 访问目标服务 '{server.server_id}'")
        print(f"{'='*60}")

        # 生成新的认证器（用服务会话密钥 K_c_s 加密）
        authenticator = Authenticator(
            client_id=self.client_id,
            timestamp=time.time(),
        )
        encrypted_authenticator = encrypt_message(
            self.session_key_c_s, authenticator.to_string()
        )

        # 访问目标服务
        response = server.handle_request(
            client_id=self.client_id,
            encrypted_service_ticket=self.service_ticket,
            encrypted_authenticator=encrypted_authenticator,
        )

        print(f"  📨 服务器响应: {response}")
        return response


# ============================================================================
#  TargetServer —— 目标服务端
# ============================================================================

class TargetServer:
    """
    Kerberos 中的目标服务（如文件服务器、打印服务器等）。
    
    职责：
    1. 接收客户端发来的 Service Ticket 和 Authenticator
    2. 用自己的长期密钥解密 Service Ticket，提取会话密钥 K_c_s
    3. 用 K_c_s 解密 Authenticator，验证客户端身份
    4. 验证通过后提供服务，也可以选择返回确认消息实现双向认证
    """
    
    def __init__(self, server_id: str):
        """
        参数:
            server_id: 服务标识（如 "FileServer"）
        
        服务端会生成一个长期密钥，并在 KDC 上注册。
        """
        self.server_id = server_id
        # 生成服务的长期密钥（在真实环境中由管理员预先配置）
        self.long_term_key = generate_fernet_key()
        print(f"\n  [服务端 '{server_id}' 初始化]")
        print(f"  ├─ 长期密钥: "
              f"{base64.urlsafe_b64encode(self.long_term_key).decode()[:16]}...")
        print(f"  └─ 请将此密钥注册到 KDC\n")

    def handle_request(self, client_id: str, encrypted_service_ticket: bytes,
                       encrypted_authenticator: bytes) -> str:
        """
        处理客户端的访问请求（第5步和第6步）。
        
        验证流程：
        ① 用自己的长期密钥解密 Service Ticket
           → 提取 {client_id, K_c_s, 有效期}
        ② 检查票据是否过期
        ③ 用 K_c_s 解密 Authenticator
           → 验证客户端身份和时间戳
        ④ 全部通过 → 提供服务
        
        关键安全特性：
        - 服务端不需要和客户端直接交换密钥
        - 服务端不需要和 KDC 实时通信（可以离线验证票据）
        - 所有信任建立在 KDC 签发的 Service Ticket 上
        """
        # ---- ① 解密 Service Ticket ----
        try:
            ticket_str = decrypt_message(self.long_term_key,
                                         encrypted_service_ticket)
            ticket = Ticket.from_string(ticket_str)
        except Exception as e:
            return f"❌ Service Ticket 解密失败: {e}"

        # ---- ② 验证 Service Ticket ----
        if ticket.is_expired():
            return "❌ Service Ticket 已过期"

        if ticket.client_id != client_id:
            return "❌ Service Ticket 中的客户端 ID 不匹配"

        if ticket.server_id != self.server_id:
            return f"❌ Service Ticket 不是颁发给 '{self.server_id}' 的"

        print(f"  [服务端] ✅ Service Ticket 验证通过")
        print(f"  [服务端] 🔑 提取会话密钥 K_c_s")

        # ---- ③ 解密并验证 Authenticator ----
        session_key_c_s = ticket.session_key
        try:
            auth_str = decrypt_message(session_key_c_s, encrypted_authenticator)
            auth_parts = dict(item.split("=") for item in auth_str.split("|"))
        except Exception as e:
            return f"❌ 认证器解密失败: {e}"

        if auth_parts["client"] != client_id:
            return "❌ 认证器中的客户端 ID 不匹配"

        # 时间戳检查（防重放攻击）
        auth_time = float(auth_parts["timestamp"])
        if abs(time.time() - auth_time) > 300:
            return "❌ 认证器时间戳无效（可能为重放攻击）"

        print(f"  [服务端] ✅ 认证器验证通过（时间偏差: {time.time() - auth_time:.1f} 秒）")

        # ---- ④ 全部验证通过，提供服务 ----
        print(f"  [服务端] ✅ 所有验证通过！\n")

        # ---- ⑤ 可选的第6步：返回确认消息（双向认证）----
        # 服务端用 K_c_s 加密一个确认消息返回给客户端
        # 这样客户端也能确认自己连接的是真正的服务端（而不是中间人）
        confirmation = encrypt_message(
            session_key_c_s,
            f"ACK:{auth_time + 1}"  # 时间戳+1，证明是当前会话的响应
        )
        # 返回确认消息的 base64 表示（模拟网络传输）
        return f"✅ 服务访问成功! 确认码: {base64.urlsafe_b64encode(confirmation).decode()[:20]}..."


# ============================================================================
#  主流程演示
# ============================================================================

def run_kerberos_demo():
    """
    运行完整的 Kerberos 密钥分配协议演示。
    
    演示流程：
    ┌──────────────────────────────────────────────────────────────────┐
    │  初始化阶段:                                                      │
    │  ① 启动 KDC（密钥分发中心）                                       │
    │  ② 创建目标服务（文件服务器），注册到 KDC                          │
    │                                                                  │
    │  认证和访问阶段:                                                  │
    │  ③ Alice 向 AS 请求认证 → 获得 TGT 和会话密钥 K_c_tgs            │
    │  ④ Alice 向 TGS 请求访问 FileServer → 获得服务票据和 K_c_s       │
    │  ⑤ Alice 使用服务票据访问 FileServer → 验证通过，服务响应         │
    └──────────────────────────────────────────────────────────────────┘
    """
    print("\n" + "="*60)
    print("  🔐 Kerberos 密钥分配协议演示")
    print("="*60)

    # ======================== 初始化阶段 ========================

    print("\n" + "-"*60)
    print("  【初始化阶段】")
    print("-"*60)

    # ① 启动 KDC
    kdc = KDC()

    # ② 创建目标服务并注册到 KDC
    file_server = TargetServer("FileServer")
    kdc.register_service(file_server.server_id, file_server.long_term_key)

    # ======================== 认证和访问阶段 ========================

    print("\n" + "-"*60)
    print("  【认证和访问阶段】")
    print("-"*60)

    # ③ 创建客户端 Alice
    alice = Client("Alice", "alice_password_123")

    # ④ Alice 向 AS 请求 TGT（第1-2步）
    if not alice.request_tgt(kdc):
        return

    # ⑤ Alice 向 TGS 请求访问 FileServer（第3-4步）
    if not alice.request_service_access(kdc, "FileServer"):
        return

    # ⑥ Alice 访问 FileServer（第5-6步）
    response = alice.access_service(file_server)

    # ======================== 演示完成 ========================

    print("\n" + "="*60)
    print("  ✅ Kerberos 协议演示完成!")
    print("="*60)
    print()
    print("  📌 核心要点回顾:")
    print("  ┌─────────────────────────────────────────────────────────┐")
    print("  │ ① 用户密码从未在网络中传输，仅用于派生密钥解密会话密钥  │")
    print("  │ ② TGT 用 TGS 密钥加密，客户端无法伪造或篡改            │")
    print("  │ ③ Service Ticket 用目标服务密钥加密，TGS 也无法伪造     │")
    print("  │ ④ 认证器含时间戳，防止重放攻击                         │")
    print("  │ ⑤ 会话密钥一次性使用，定期更换，保证前向安全性         │")
    print("  └─────────────────────────────────────────────────────────┘")


# ============================================================================
#  程序入口
# ============================================================================

if __name__ == "__main__":
    run_kerberos_demo()
