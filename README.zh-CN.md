# InjectorKit

[English](README.md) · 简体中文 · [使用指南](GUIDE.zh-CN.md)

覆盖多个漏洞类别的 Web 漏洞利用工具，用于 CTF 与授权渗透测试。

它是流量驱动扫描器的进攻侧对应物：扫描器回答"这个参数有没有漏洞"，InjectorKit 回答"怎么进去、进去之后做什么"。它探测、读证据、决定下一步、在过滤器拦住时换手法，直到拿到利用点，或者证明这条路走不通。

同一套引擎，多个类别：SSRF、PHP 与 Java 伪协议（`php://`、`gopher://`、`dict://`、`data://`、`phar://`、`jar:`、`jrt:`）、命令注入，以及通过 `phar://` 与 `unserialize()` 的反序列化——最后这个走 `proto`，因为它要的是一个 wrapper 和一个被应用交给反序列化器的值。类别共用引擎，所以加一类是加知识，不是加一个扫描器。

## 从这三条开始

给它一个带参数的 URL 就够了。工具自己找参数、问目标能接受什么，然后告诉你它证成了什么：

    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"
    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1"

带 body 的请求默认就是表单 POST，所以表单后面的参数用 `--data` 而不是查询串：

    python injectorkit.py proto -u "http://target/" --data "file=index.php" --param file

页面是表单提交而不是查询串时，让它自己读表单：

    python injectorkit.py proto -u "http://target/" --forms

已经知道要读哪个文件就直接说——工具会去问那一个，不再自己猜：

    python injectorkit.py proto -u "http://target/?file=x" --read /flag

要利用而不只是发现，直接点名要。**命名命令本身就是授权**，所以只有一个旗标、不是两个：

    python injectorkit.py proto -u "http://target/?file=x" --os-cmd 'id'
    python injectorkit.py proto -u "http://target/?file=x" --os-shell

`--exploit` 是另一回事：它表示**工具可以自己往下走**——造一条链发出去、往 web 目录写文件、往日志里种代码——而不只是报告它证成了什么。

每次运行都会边跑边报它在做什么，结尾给出：证成了什么、排除了什么、还有什么没测到。`-q` 只留结果，`-v` 连请求一起打。`python injectorkit.py <类别> -h` 看该类别的选项。

工具本身只输出英文，不提供中文界面；本文件只是中文说明。

## 环境要求

Python 3.11 或更新。核心零第三方依赖，检出即可运行。经 interactsh 部署做带外测试需要 `cryptography`（安全工具环境通常已有）；没有它时，本地监听器仍然可用。

## 测试

    python -m unittest discover -s tests -t .

离线：不需要目标、不需要网络、不需要 PHP、不用装任何东西。覆盖的是各模块依赖的那几层——报文解析、参数位置、变异代际、证据判定、板书、先验、协议字节、filter chain 的长度、输出规则。

`lab/` 是开发时用的靶场，`lab/acceptance.py` 是发版前的验收：13 个场景，每个都跑两遍——一遍手工、一遍工具——再比对。这两样都是开发 InjectorKit 用的，工具本身不依赖它们。

## 登录之后

把工具指向你已经登录的身份就行——不需要配置什么，也不需要它自己去登录：

    python injectorkit.py ssrf -u "http://target/admin/export?file=x" \
        -C "PHPSESSID=abc123; csrf=xyz" \
        -H "Authorization: Bearer eyJhbGciOi..."

- `-C/--cookie` 直接收浏览器里那样的 cookie 串；整行粘过来的 `Cookie: ...` 也照收不误。
- `-H/--header` 管其余的——bearer token、API key、自家鉴权头。`-H` 指定的头同时也会成为可注入的位置，自定义鉴权头只有这样才测得到。
- `--basic-auth USER:PASSWORD` 帮你编码。

有两条规则是为了让它对活着的会话安全：cookie 与请求自带的**合并**而不是替换——否则请求里的 CSRF token 会被丢掉，正好把要保的会话搞掉；请求自己已经指定的头优先于命令行给的值，因为请求里的身份比一个默认值更具体。

## 用法

每种漏洞类型是一个子命令，各自有专属选项，再加上所有子命令共享的引擎选项（传输、绕过预算、进度存储、详细程度）。常见的几条：

    python injectorkit.py -h
    python injectorkit.py ssrf -h
    python injectorkit.py ssrf -u "http://target/api/fetch?url=x" --param url --oob 10.0.0.5:8081
    python injectorkit.py ssrf -u "http://target/api/fetch?url=x" --oob-interactsh oast.pro
    python injectorkit.py proto -r burp.txt --param file --oob 10.0.0.5:8081
    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1"

`-r` 收一份原始 HTTP 报文（Burp 里复制出来的那种），报文里的每个参数位置都会成为可注入点。

目前三个类别：`ssrf` 问 URL 参数能到达哪里；`proto` 问路径参数接受什么、又会交回什么；`cmdi` 问参数够得着哪个 shell、在那里能跑什么。

### 命令注入

问题是算术：工具让目标打印两个新生成的标记，中间夹一个算出来的数字。回显输入的页面会把**表达式**还回来，只有真的跑过的 shell 才会还回**那个数字**。payload 本身不含答案，所以页面回显自证不了。

因为这个问题不依赖具体 shell，shell 就成了**要搜索的量**而不是前提。`sh`、`bash`、PowerShell 和 Windows 命令解释器被建模成"能打印字面量、也能打印和"的语言，再和"命令怎么起头"叉乘——值本身就是整条命令，或者它是页面已经在跑的某条命令的参数、得先把它结束掉。在这里"没被拦住"不算答对，所以搜索会一直往上爬，直到真的有东西跑起来。

跑通之后，`--os-cmd` 会沿着证成的那个形态执行一条命令；`--os-shell` 则把它留着，你敲什么它就执行什么——终端可以，管道也可以，所以脚本化会话能跑。如果链在"证成"和"使用"之间失效了，它如实说没跑，而不是把页面当输出：

    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1" \
        --os-cmd 'id; uname -a'
    python injectorkit.py cmdi -u "http://target/ping?host=127.0.0.1" --os-shell

命令打印出来的东西属于结果，所以它出现在**最后的** `Commands run:` 下面、只出现一次——读到的文件出现在 `Files read:` 也是同一个地方。

### 拿 shell

穿过一个 `include()` 点拿到执行有两条路，走哪条由目标决定，不是偏好问题：

- 默认现场生成一条 `php://filter` 链来跑 —— `--os-shell` 给一个会话，`--os-cmd` 只跑一条命令。这要求应用接受 `php://filter`。
- `--log-path /var/log/nginx/access.log` 把 PHP 源码种进服务器自己写的文件里，再 include 它。这条路只要纯路径 —— 而拒绝一切 wrapper 的目标，恰好只放行纯路径。

    python injectorkit.py proto -u "https://target/" --forms \
        --log-path /var/log/nginx/access.log --os-cmd 'id'

### 走到反序列化

`--make-phar` 在本地生成归档，因为造一个 phar 不该要求本机装 PHP：

    python injectorkit.py proto -u "https://target/" --make-phar evil.phar \
        --phar-class SomeFrameworkClass --phar-set 'path=/tmp/pwn'

自己传上去，再用 `--upload` 指向它的落点。用之前值得知道：**PHP 8 上打开 phar 不会反序列化 metadata**，只有 `(new Phar(...))->getMetadata()` 会，所以这条链需要目标主动去取 metadata —— 框架代码会，裸 `include` 不会。

### 同一个扫描跑第二遍

进度默认存在 `.injectorkit/` 下，按主机与页面分。在一个页面上跑过的动作不会再跑，所以同一页面扫第二遍几乎不发包，而不是把已经写在板上的答案重新问一遍。

    --flush-session     忘掉之前几次跑在这个主机上学到的东西
    --state FILE        改用你自己指定的位置
    --retries N         连接掉线后重试几次（默认 1）

### 回调

盲 SSRF、盲命令注入、盲 XXE 在响应里不留任何痕迹，唯一的证据是目标向攻击者指定的地址发起的连接。接收方式有两种，选哪种取决于目标能连到哪里：

    --oob 10.0.0.5:8081        在本机起监听器；目标必须能连到这台机器
    --oob-interactsh oast.pro  用一个公共或自建的 interactsh 部署；回调域名
                               从任何位置都能解析，这才是 NAT 后面打公网目标可用的方式

私有部署再加 `--oob-token`。两个都不给时，带外动作会自己跳过，而不是发出注定收不到回执的 payload。

### 绕过过滤器

    --via "http://allowed/redirect?to={target}"

黑名单可以讲道理：地址写法、编码层级、DNS 别名都能给它新的漏网之鱼。白名单不行 —— 目的地必须以过滤器接受的形态出现、再落到别处，这就是 `--via` 的用途。模板由使用者提供，因为只有他知道目标信任什么。

开箱即用的绕过能力：

- inet_aton 风格解析器接受的地址写法：十进制、八进制（补零或不补）、十六进制、短形式、IPv4-mapped IPv6、结尾加点
- 解析回内网地址的 DNS 别名（`127.0.0.1.nip.io`），解析型过滤器同样看不穿
- `--rebind INTERNAL,EXTERNAL`：把每个目的地再以一个在内外网地址之间交替的域名试一次 —— 这能过"解析一次、稍后再连"的检查
- 用 gopher 写出的完整 HTTP 请求，这是够到那些要求 `Metadata-Flavor: Google` 或 `Metadata: true` 的元数据服务的唯一办法，URL 参数加不了请求头
- 由两个参数拼出的目的地（`?host=&path=`），任何单参数 payload 都填不满

### 参数到底在哪里

一个 URL 只能碰到 URL 里的参数，其余都在 body 里：

    --forms              抓取页面并提交它声明的每个表单，字段照页面声明填
    --targets targets.txt  一行一个目标 —— 一个 URL，或者一个保存下来的原始报文路径

`--forms` 让登录页、搜索框、上传控件都能从单个地址开始测：请求按页面构造请求的方式构造（GET 字段进查询串、POST 字段进 body、上传表单发真正的 multipart），每个表单都成为独立目标。

参数按它所在的位置寻址：`query:url`、`body:url`、`cookie:url`、`multipart:url`、`json:user.avatar`，以及 `json -> ref` 表示"参数值本身是一个 JSON 文档、字段在其中"。

### 对已发现的东西动手

    --exploit --webroot /var/www/html              通过 Redis 写 webshell
    --exploit --fpm-script /var/www/html/index.php 通过 PHP-FPM 执行代码

默认关闭 —— 在目标上写文件或执行命令是使用者的决定，不是扫描器替他做的。开启后，后续动作由指纹派生：地址和端口来自应答的服务，路径来自使用者，并且结果会被验证：写进去但跑不起来的 shell 会被如实报告。

## 工作原理

一份固定的 payload 列表只能把一个问题回答一次，而真实目标只回答一部分：某个 scheme 被拦了但别名没拦，某个端口被过滤但重定向没被过滤，某个服务应答但只在正确的握手之后。通往利用的路径是一连串问题，每个答案都改变下一个该问什么。

所以工作单元是共享事实之上的一次状态转移：

    状态 + 证据 -> 下一个状态、下一个动作

每个模块提供一张状态图。共享黑板书保存已学到的东西：可达端口、回显通道（直接回显、报错回显、只能靠时间、只能靠带外）、过滤画像、被接受的协议、已指纹的内网服务，以及不许再试的死路。

payload 从不被存储，而是被推导：语义正确的种子加上保持语义的变形器，按"代"排序；连续被拒才升级，并把能通过的那一代记下来，后续动作从那一代起步。

哪一步变形先试是学出来的，不是写死的。每个穿过过滤器的变形沉淀权重，被拒的扣掉权重，权重随时间蒸发 —— 这样在一个目标上得到的结论不会永远生效。这张表存在 `.injectorkit/pheromone.json`，跨目标共享，这也是"打一连串目标时第二个比第一个便宜"的原因。它只决定尝试顺序，从不判定某个尝试不可能。`--no-pheromone` 关掉它，`--pheromone-file` 换位置。

判定只认证据：只有目标才会产生的特征串、把请求的编码还原之后才出现的内容、落在请求区间内的延迟、或者到达监听器的回连。响应发生变化不算发现，而"不再被过滤器拒"也不算命中 —— 只是不再被拒的变形，拿到的权重要低得多。

## 许可

MIT，见 [LICENSE](LICENSE)。

作者：coolmoon & guaidao2。
