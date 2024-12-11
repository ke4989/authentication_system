实现一个简单的基于时间一次性密码（TOTP, Time-based One-Time Password）的身份鉴别系统：

1. 一个基于python flask框架实现后端的网页登录系统；
2. 使用TOTP以及用户密码的多因素身份鉴别；
3. 基于ECDH的密钥交换及传输数据加密。

开始：

```shell
pip install -r requirements.txt
python ./code/main.py
```

网页html需自行部署（如使用VS Code的Live Server插件）
