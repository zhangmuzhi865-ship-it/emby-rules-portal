# Emby 直连规则管理 · Cloudflare Worker + D1 多用户版

给自己的 Emby 服务器做直连规则：多个人各管各的规则，各拿各的订阅链接，不用再互相传配置文件。

**你得到的是什么**

- 一个网页管理后台：账号密码登录，在线加规则、删规则、改密码
- 每个用户一条独立的订阅链接，Loon、Surge、Quantumult X、Clash 四种格式都有，改完规则客户端刷新订阅就同步
- 管理员可以在页面里直接建用户、重置密码、删号，不用碰数据库
- IPv6 固定 Host 插件（`.plugin` / `.sgmodule`），定时自动跟着 Emby 域名的当前 IPv6 变
- 不用自己养服务器：一个 Cloudflare Worker + 一个 D1 数据库，免费计划就能跑

**怎么跑起来的**

```text
浏览器 --HTTPS--> Cloudflare Worker (rules.example.com)
                     |-- D1 数据库：用户、密码哈希、规则、订阅 token
                     └-- 每 5 分钟：查 Emby 域名的 AAAA，更新 IPv6 插件
Loon / Surge / QX / Clash --HTTPS--> 订阅链接（按用户 token 区分）
```

## 部署步骤

照着走，大概 10 分钟。

### 0. 准备

- 一个 Cloudflare 账号，一个已经接入 Cloudflare 的域名
- 本机装 Node.js 18+，再装 Wrangler：
  ```bash
  npm install -g wrangler
  npx wrangler login
  ```
  按提示在浏览器里点授权，回到终端看到登录成功就行。

### 1. 拉代码、填配置

```bash
git clone https://github.com/<你的用户名>/emby-rules-portal.git
cd emby-rules-portal
cp wrangler.toml.example wrangler.toml
```

打开 `wrangler.toml`，改四处（别的不用动）：

| 位置 | 改成什么 |
| --- | --- |
| `routes` | 你的域名和路由，比如 `rules.example.com/*`，`zone_name` 填你的域名 |
| `database_id` | 先空着，下一步建完 D1 再填回来 |
| `[vars] PUBLIC_BASE_URL` | 你的完整地址，比如 `https://rules.example.com`，不要带尾斜杠。订阅链接按这个生成，必须和路由一致 |
| `[vars] DEFAULT_IPV6_HOST_DOMAIN` | 你的 Emby 域名；不用 IPv6 插件就留空 |

### 2. 建 D1 数据库、跑迁移

```bash
npx wrangler d1 create emby-rules-portal
```

输出里有一行 `database_id`，把它填回 `wrangler.toml`，然后：

```bash
npx wrangler d1 migrations apply DB --remote
```

看到两个迁移都打勾就是成功了。这一步只建表，不建任何用户，账号密码和 token 都不会进仓库。

### 3. 建第一个管理员账号

```bash
node scripts/setup-admin.mjs <用户名> <密码>
# 比如：node scripts/setup-admin.mjs admin '你的密码'
```

- 用户名：3–32 位，只能用小写字母、数字、下划线、连字符
- 密码：8–128 位
- 建好后是 `owner`（管理员）角色，初始 0 条规则

密码只在内存里算哈希，不会存明文，也不会打印出来。这个密码丢了找不回来，只能由管理员重置，所以记好。

### 4. 部署 Worker

```bash
npx wrangler deploy
```

看到 `Uploaded ... / Deployed ... triggers` 就是部署成功了。

部署完先验证两下：

```bash
curl https://<你的域名>/healthz
# 应该返回 ok
```

然后浏览器打开 `https://<你的域名>/login`，用刚建的账号登录，能进 `/app` 就说明全通了。

### 5.（可选）IPv6 插件自动同步

Worker 里自带一个每 5 分钟的定时同步（`wrangler.toml` 里的 `[triggers] crons`）。

注意：Cloudflare 免费账号最多 5 个 cron 触发器。如果你的名额已经满了，部署时会报 `code: 10072`，不用慌，Worker 本身不受影响，只是缺这个定时同步。替代办法是在你自己的服务器上每 5 分钟跑一次：

```bash
CLOUDFLARE_API_TOKEN=<有 D1 写权限的 API Token> \
CLOUDFLARE_ACCOUNT_ID=<你的账号 ID> \
D1_DATABASE_ID=<数据库 ID> \
python3 scripts/sync-ipv6-d1.py
```

Token 只需要 D1 写权限，别给多余权限。

## 平时怎么用

### 登录

`https://<你的域名>/login`。用户名不区分大小写，`Admin` 和 `admin` 都能进。

### 加规则

在 `/app` 里粘贴 Emby 地址，比如 `https://emby.example.com:12307/emby`，点“添加直连”。端口和路径会自动去掉，只留域名生成规则。占位符（比如 `example.com`）不会被添加。

### 匹配类型

每条规则都有一个匹配类型，决定它怎么命中域名。添加时在输入框旁边的下拉框里选，默认是后缀匹配；已有的规则点它后面的类型按钮（删除按钮左边）就能切换，顺序是后缀 → 精确 → 包含 → 后缀。批量粘贴时也可以选一个默认类型；如果粘贴的内容里某行本身就写着 `DOMAIN,域名` / `DOMAIN-SUFFIX,域名` / `DOMAIN-KEYWORD,关键词`，那行会保留自己写明的类型。

| 类型 | 含义 | 适用场景 |
| --- | --- | --- |
| `DOMAIN-SUFFIX`（后缀匹配，默认） | 域名本身和它的全部子域名都命中 | 绝大多数 Emby 线路都用这个 |
| `DOMAIN`（精确匹配） | 只命中这一个域名本身，子域名不算 | 主域名要直连、子域名要走代理的特殊情况 |
| `DOMAIN-KEYWORD`（包含匹配） | 域名里包含这个词就命中 | 想用一个词兜住一批变体域名时用；容易误伤，别当默认 |
| `IP-CIDR` / `IP-CIDR6` | 命中这个 IP | 贴 IP 地址时自动生成，不能改匹配类型 |

四种订阅格式都会正确转换：Loon 和 Surge 直接用 `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD`；QX 转成 `host` / `host-suffix` / `host-keyword`；Clash 用同样的三个类型。正则（`DOMAIN-REGEX`）和按国家匹配（`GEOIP`）没有接进来：前者容易写错还拖垮整组规则，后者跟“指定几个 Emby 线路域名”不是一回事。

### 批量粘贴线路

`/app` 里还有一个“批量粘贴线路”框：把服务商发来的整段线路通知原样粘贴进去，点“识别并全部添加”，它会把里面所有的链接和域名都识别出来，去重后一次性加入规则集。比如：

```text
1. CF线路1号
   https://line1.example.com:443
2. CF线路2号
   https://line2.example.com:443
```

- 按编号识别每条线路的名字，添加结果里会显示“线路名 → 规则”，方便核对
- 端口和路径自动去掉；重复的只加一次；已经在规则集里的会报“已存在”
- 示例占位符、格式不对的地址会跳过，并告诉你跳过的原因
- 一次最多处理 200 条，粘贴内容最多 10 万字

### 订阅地址

`/app` 里的“订阅地址”有四条，按你用的软件复制对应那条，加为远程规则 / 规则集，策略选 DIRECT（QX 已经内置了 direct，不用再选）：

| 软件 | 文件 |
| --- | --- |
| Loon / Shadowrocket | `emby-direct.list` |
| Surge | `emby-direct-surge.list` |
| Quantumult X | `emby-direct-qx.list` |
| Clash / Stash / Mihomo | `emby-direct-clash.yaml` |

另外还有两条 IPv6 插件地址：`emby-v6-host.plugin`（Loon）和 `emby-v6-host.sgmodule`（Surge 模块）。在 `/app` 里改规则后，订阅内容跟着变，客户端下次刷新订阅就同步过去。

### 管用户（管理员）

登录后拉到页面最下面，“用户管理”只有管理员能看到：

- **用户列表**：用户名、角色、规则数、设没设密码
- **新建用户**：填用户名、初始密码、选角色（普通用户 / 管理员），新号 0 条规则起步
- **重置密码**：下拉框选人，填新密码，点按钮。改完那个人要重新登录
- **删除用户**：连规则带订阅链接一起删；不能删自己的账号

普通用户登录是看不到这个入口的，接口那边也拦着。

### 改自己的密码

每个用户在自己页面最下面的“修改密码”里改，要输旧密码。改完当前登录保持有效，其他设备会被退出。

## 安全说明

- 密码存的是 PBKDF2-SHA256 哈希（10 万次迭代），不是明文
- 每个用户的订阅和管理链接都带一串随机 token，别分享给不信任的人
- 登录有防爆破限流：同一个 IP 15 分钟内错 5 次，或同一个账号 15 分钟内错 10 次，就锁 15 分钟（返回 429）；登录成功会清掉计数。锁账号是按用户名算的，攻击者知道用户名就能把对应账号锁 15 分钟，所以用户名也别起得太好猜，密码更要够强
- 仓库里没有任何真实账号、密码、token、域名和规则数据：`wrangler.toml` 是模板，种子迁移不建用户，管理员账号由部署时现建；部署用的 API Token 只存在你自己的机器上，别提交进仓库

## 从旧版 Python 面板迁移

如果你之前用的是 vps-la 上那套 Python 版面板，想让原来的订阅链接继续生效：迁移用户时保留原来的 `admin_token` 和 `sub_token` 不变，只把规则数据和密码哈希写进 D1。域名、token、文件名都不变，客户端不用改任何订阅地址。

## 常见问题

- **登录报“用户名或密码错误”**：先确认密码是不是原样，包括末尾的符号；用户名不区分大小写，首字母大写也没关系
- **登录报“登录尝试次数过多，请 15 分钟后再试”**：触发了防爆破限流，等 15 分钟再试；如果是你自己连续输错，等锁过期后一次输对就能进，成功登录会清掉计数
- **登录后显示“读取规则失败”**：旧版本 `/app` 页调接口用的相对地址，在没有尾斜杠的 `/app` 下会解析错；当前版本已改成绝对地址，刷新页面即可
- **部署时 cron 报错 10072**：免费账号触发器名额满了，按上面第 5 步用外部脚本同步，Worker 不受影响
- **改密码要求至少 8 位**：页面改密码和管理员重置密码都要求 8–128 位
- **新建用户是 0 条规则**：正常。新用户从空白开始，在自己的页面里加规则

## License

MIT
