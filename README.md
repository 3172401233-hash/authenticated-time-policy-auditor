# authenticated-time-policy-auditor

离线认证时间策略审计库（Node.js，零依赖）。输入多个可信时间源的签名时间戳、
服务器单调时钟、当前 UTC 与来源优先级，输出每个请求的接受/拒绝审计决定。

## 功能

- 验签：Ed25519 签名时间戳，校验来源证书标识（certId）与密钥有效期
- 共识：按来源优先级加权的多数派时间共识，分歧时保持上次可信时间并拒绝服务（fail closed）
- 漂移：非对称校正窗口，同时接受窗口内的旧时间戳与新时间戳
- 重放：有界 nonce 重放窗口（容量上限 + TTL），可持久化，重启后 nonce 不可重用
- 断网：短暂断网期间用单调时钟推进可信时间，超过 `maxPartitionMs` 后拒绝服务
- 回拨：系统时钟回拨时可信时间只增不减；不会用单调计数器去"抵消"回拨后的 UTC
- 闰秒：支持闰秒平滑（smear）窗口，窗口内自动放宽偏移容忍
- 密钥轮换：新旧密钥按 `notBefore`/`notAfter` 重叠共存，按签发时间选钥

## 用法

```js
const { TimePolicyAuditor, Keyring } = require('./index.js');

const keyring = new Keyring();
keyring.addSource('ntp-1', {
  priority: 2,
  certIds: ['cert-fp-1'],
  keys: [{ keyId: 'k1', publicKey: pem, notBefore: 0, notAfter: T }],
});

const auditor = new TimePolicyAuditor({ keyring, stateFile: './auditor-state.json' });
auditor.ingestStatement(signedTimestamp);          // 维护可信时间
const decision = auditor.authorize({ nonce, timestamp: clientTs });
```

时钟可注入（`now` / `monotonicNow`），便于测试与仿真。

## 完整性假设

1. 多数派可信：按优先级加权后，严格多数权重的时间源在 `consensusToleranceMs`
   内一致；否则审计器拒绝授权而不是猜测时间。
2. 密钥安全：来源私钥未泄露；密钥轮换通过重叠有效期完成，签名按 `issuedAt`
   落在密钥有效期内才可用。
3. 单调时钟可信但有限：单调时钟只用于正向推进可信时间，且断网推进上限为
   `maxPartitionMs`；它永远不被用来把可信时间往回拨，也不用于抵消 UTC 回拨。
4. 持久化原子性：`stateFile` 通过临时文件 + rename 原子写入；状态文件损坏时
   重放窗口清空但时间下限丢失，部署时应配合只增的外部时间锚。
5. 重放保护地平线：nonce 保护期 = `replayWindowTtlMs`，且在容量
   `replayWindowSize` 耗尽时最旧条目被逐出——超出容量或 TTL 的重放不再被识别。
6. 请求方时钟不要求精确：只要落在校正窗口内即可，超出即拒绝。

## 最大可接受偏差（默认值，均可配置）

| 参数 | 默认 | 含义 |
| --- | --- | --- |
| `consensusToleranceMs` | 2000 | 时间源之间允许的最大分歧 |
| `maxFutureSkewMs` | 2000 | 请求时间戳允许超前的边界 |
| `maxPastSkewMs` | 5000 | 校正窗口内允许接受的旧时间戳 |
| `statementTtlMs` | 30000 | 时间源声明的新鲜度 |
| `maxPartitionMs` | 60000 | 断网后仅靠单调时钟维持的最长时长 |
| `replayWindowTtlMs` | 600000 | nonce 重放保护期 |
| `replayWindowSize` | 10000 | 重放窗口容量上限 |

闰秒平滑窗口（`leapSmear: { startMs, endMs, offsetMs }`）期间，上述偏移容忍
自动加上当前平滑偏移量的绝对值。

## 测试

```sh
node --test
```

覆盖：多数派共识、冲突时间、nonce 重放、重启恢复、边界超前、时钟漂移、
时钟回拨、断网降级、签名过期、密钥重叠、闰秒平滑、有界重放窗口逐出。
