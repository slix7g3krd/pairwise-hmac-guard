# pairwise-hmac-guard

开放平台要求每个请求带签名后，重放和篡改就开始出现：签名只覆盖 path，不覆盖 query；参数排序规则和客户端不一致；重复参数只取第一个，后端取最后一个；body 的 hash 没进签名；时间戳允许无限旧；nonce 只存在进程内，多实例各算各的；签名比较用普通等号，存在时序侧信道；密钥轮换后旧密钥永久有效；空 body 和 `{}` 算出同一个签名；签名头名大小写不统一。security/hmac_guard.py 是核心，tests/test_hmac_guard.py 15个红。要修的是：全量 canonical 串；稳定排序；重复参数拒绝；body hash 入签；时间窗限制；nonce 共享存储；常量时间比较；密钥版本与过期；空 body 区分；头名归一。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
