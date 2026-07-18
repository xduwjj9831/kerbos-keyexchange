# Kerberos Key Exchange Protocol Simulation

Kerberos 密钥分配协议的 Python 模拟实现。该项目使用 `cryptography` 库的 Fernet 对称加密，完整模拟了 Kerberos 认证协议的 6 步核心流程。

## Overview

[Kerberos](https://en.wikipedia.org/wiki/Kerberos_(protocol)) 是由 MIT 开发的基于对称密钥的网络认证协议，广泛应用于 Windows Active Directory、Hadoop 等系统中。

本项目以教学为目的，用简洁的 Python 代码实现了 Kerberos 的核心思想，帮助你直观理解：

- 票据授权票据（TGT, Ticket-Granting Ticket）的签发与使用
- 服务票据（Service Ticket）的申请与验证
- 会话密钥的分发与安全传递
- 认证器（Authenticator）防止重放攻击
- 双因子认证的回调确认

## Protocol Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│  1. Client ──────→ AS   : "我是 Alice，我想访问服务"                │
│  2. AS    ──────→ Client: {K_c_tgs}K_c + TGT = {K_c_tgs, Alice}K_tgs│
│              （用客户端密码加密的会话密钥 + 票据授权票据）           │
│  3. Client ──────→ TGS  : TGT + Authenticator = {Alice, 时间戳}K_tgs│
│  4. TGS   ──────→ Client: {K_c_s}K_c_tgs + Service Ticket          │
│              （用会话密钥加密的服务密钥 + 服务票据）                 │
│  5. Client ──────→ Server: Service Ticket + Authenticator           │
│  6. Server ──────→ Client: {时间戳+1}K_c_s（可选，双向认证）        │
└─────────────────────────────────────────────────────────────────────┘
```

### Roles

| Role | Description |
|------|-------------|
| **KDC** | Key Distribution Center，密钥分发中心，可信任的第三方 |
| ├── **AS** | Authentication Service，认证服务，验证用户身份并签发 TGT |
| └── **TGS** | Ticket Granting Service，票据授权服务，验证 TGT 并签发服务票据 |
| **Client** | 客户端（用户），需要访问目标服务的一方 |
| **Server** | 目标服务端（如文件服务器、打印服务器），提供实际服务的一方 |

## Project Structure

```
kerbos-keyexchange/
├── kerbo.py              # Kerberos 协议核心实现（入口文件）
├── learn.py              # Python 类与继承学习示例（独立）
├── learn_class.py        # Python 面向对象编程教程（独立）
├── requirements.txt      # 项目依赖
└── .gitignore
```

> `learn.py` / `learn_class.py` 是学习 Python OOP 时附带的示例文件，与 Kerberos 协议无关，可独立运行。

## Getting Started

### Prerequisites

- Python 3.8+
- pip（Python 包管理器）

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/<your-username>/kerbos-keyexchange.git
cd kerbos-keyexchange

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the Kerberos protocol simulation
python kerbo.py
```

### Run the Python Tutorials (Optional)

```bash
python learn_class.py   # Python 类、继承、属性、魔术方法教程
python learn.py         # Person 类简单测试
```

## Core Implementation

### Ticket（票据）

票据是 Kerberos 协议中最核心的数据结构。票据由 KDC 签发，包含用户的身份信息与会话密钥，并使用目标服务（TGS 或目标 Server）的密钥加密。客户端无法篡改票据内容。

- **TGT (Ticket-Granting Ticket)**: 由 AS 使用 TGS 的长期密钥加密，有效期通常为 1 小时
- **Service Ticket**: 由 TGS 使用目标服务的长期密钥加密，有效期较短（10 分钟）

### Authenticator（认证器）

认证器由客户端自己生成，使用会话密钥加密。它包含客户端 ID 和时间戳，用于向服务端证明客户端"当前时刻"仍然知晓会话密钥。

认证器是一次性使用的，每次请求都需要重新生成，有效防止重放攻击。

### Security Features

1. **用户密码从未在网络上传输**：密码仅用于本地派生密钥，解密从 AS 收到的会话密钥
2. **TGT 不可伪造**：使用 TGS 密钥加密，客户端无法查看或篡改
3. **Service Ticket 不可伪造**：使用目标服务密钥加密，TGS 也无法伪造
4. **抗重放攻击**：认证器含时间戳，服务端验证时间偏差在 5 分钟内
5. **前向安全性**：会话密钥一次性使用，定期更换

## Code Review Highlights

- 使用 `cryptography.fernet.Fernet` 对称加密实现消息的加密与解密
- 使用 `PBKDF2HMAC` 从用户密码派生长期密钥
- 完整的错误处理：密码错误、票据过期、身份不匹配等场景
- 面向对象设计：KDC、Client、TargetServer 职责清晰
- Windows GBK 终端编码兼容：自动处理 emoji 字符显示问题

## License

This project is provided for educational purposes. Feel free to use, modify, and share.
