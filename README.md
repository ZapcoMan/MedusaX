<img src="https://github.com/Ascotbe/Medusa/blob/master/Medusa.png?raw=true" width="1500" alt="MedusaX" />

<p align="center">
    <a href="https://github.com/Ascotbe/Medusa"><img alt="Release" src="https://img.shields.io/badge/MedusaX-0.2.0-green"></a>
    <a href="https://github.com/Ascotbe/Medusa"><img alt="Release" src="https://img.shields.io/badge/python-3.7+-blueviolet"></a>
    <a href="https://github.com/Ascotbe/Medusa"><img alt="Release" src="https://img.shields.io/badge/Version-0.2.0-red"></a>
    <a href="https://github.com/Ascotbe/Medusa"><img alt="Release" src="https://img.shields.io/badge/LICENSE-GPL-ff69b4"></a>
    <a href="https://github.com/Ascotbe/Medusa"><img alt="Release" src="https://img.shields.io/badge/Based_on-Ascotbe%2FMedusa-orange"></a>
</p>

<h1 align="center">欢迎使用 MedusaX</h1>

## 关于 MedusaX

> **MedusaX** 是基于开源项目 [Ascotbe/Medusa](https://github.com/Ascotbe/Medusa)（美杜莎）进行二次开发的衍生版本。
>
> 本项目使用 `GPL` 协议，未经授权，禁止使用商业用途。
>
> 当前版本：`v0.2.0`（完成扫描体系重建与安全加固：插件化主动扫描、端口扫描、子域名探测、被动扫描代理、Word 报告生成全部恢复可用，并关闭 DEBUG、启用 CSRF 防护、密钥环境变量化）。

### 二次开发说明

- **上游项目**：[Ascotbe/Medusa](https://github.com/Ascotbe/Medusa)
- **本项目定位**：在保留原版核心能力的基础上进行二次开发，版本号独立演进，从 `v0.1.0` 开始。
- **当前状态**：v0.2.0 已完成方向 A（扫描体系完整重建）与方向 B（安全加固）：
  - 插件化主动扫描引擎（`Web/ActiveScan/`）：YAML 插件解析（nuclei 风格）+ CEL 表达式判定（`cel-python`），失败降级不中断任务
  - 端口扫描（`python-nmap`，Docker 内已内置 nmap 二进制）、子域名探测（DNS 枚举 + 泛解析过滤）、被动扫描代理（`PassiveScanProxy.py` + mitmproxy addon）
  - 扫描 API 层：任务下发、任务/漏洞/端口/子域名查询、报告生成与下载、被动扫描项目管理（`docs/API/主动扫描.md`、`docs/API/被动扫描.md`）
  - 安全加固：`DEBUG` 环境变量化（默认关闭）、`STATIC_ROOT` + `collectstatic` + nginx 静态托管、CSRF 全链路防护（中间件 + 前端拦截器 + csrftoken 下发接口）、`SECRET_KEY` 与 Redis 密码环境变量化、CORS 白名单收紧
  - 详细改动将随后续版本更新日志持续同步。

### 项目简介

**MedusaX** 是一个模块化、插件化的开源 Web 漏洞扫描与渗透测试平台（衍生自美杜莎 Medusa），集成了资产收集、被动/主动扫描、CVE 监控、DNSLog 漏洞验证、子域名探测、木马/免杀生成、邮件钓鱼等能力，并提供基于 Django + Vue 的可视化 Web 管理界面。

### 技术栈

| 层 | 技术 |
| --- | --- |
| 后端 | Python 3.7+、Django 3.0.5、Celery 5.2.7（异步任务）、Gunicorn、Redis（消息队列/缓存） |
| 前端 | Vue 2.6 + Vue Router + Vuex + Ant Design Vue + ECharts（Node.js 12.x–14.x，推荐 14 LTS；Vue CLI 4.5） |
| 内置服务 | HTTP 服务（`HTTPServer.py`，端口 9999）、DNS 服务（`DNSServer.py`，端口 8888，用于 DNSLog 回连验证）、被动扫描代理（`PassiveScanProxy.py`，基于 mitmproxy 的独立代理进程，用于被动流量抓取与检测） |
| 数据库 | SQLite（`Medusa.db`）+ Redis |
| 部署 | Docker（`Dockerfile`、`install.sh`）、Nginx 反向代理、Sendmail 自建邮件服务 |

## 功能模块

`Web/` 目录下的核心模块：

- **ActiveScan（主动扫描）**：插件化漏洞检测框架，扫描入口。插件位于 `Plugins/`（YAML 配置驱动）。
- **PassiveScan（被动扫描）**：被动流量漏洞检测。
- **ApplicationCollection（应用资产收集）**：识别 Web 应用、中间件、框架指纹。
- **AssetManagement（资产管理）**：资产录入与生命周期管理。
- **BasicFunctions（基础功能）**：通用工具函数库。
- **CrossSiteScriptHub（XSS）**：跨站脚本相关检测与利用。
- **CVE（CVE 漏洞）**：
  - `GithubMonitoring`：GitHub 上 CVE PoC 监控
  - `NistMonitoring`：NIST 漏洞库监控（`NistInitialization` 初始化）
- **CollaborationPlatform（协作平台）**：多人协作/团队功能。
- **DomainNameSystemLog（DNSLog）**：内置 DNS 回连服务，用于无回显漏洞验证。
- **FileAcquisition（文件获取）**：`File` / `Zip` 相关文件采集。
- **Notification（通知）**：扫描结果推送通知。
- **Subdomain（子域名）**：子域名枚举与探测。
- **SystemInfo（系统信息）**：节点/系统状态。
- **Template（模板）**：代码/报告模板。
- **ToolsUtility（工具集）**：`AntivirusSoftwareMatching`（杀软识别）、`BinaryAnalysis`（二进制分析）。
- **TrojanOrVirus（木马/免杀）**：`Modules` / `PE` / `Shellcode` / `TrojanFile`，支持 C / C++ / Go / Nim 等语言生成免杀载荷（`TrojanInterface.py`）。
- **Workbench（工作台）**：操作日志、请求日志记录。
- **Email（邮件）**：`Send` / `ReceiveData` / `Attachment` / `Graph` 等，支持钓鱼邮件投递与数据回收。
- **Image（图片）**：图片资源处理。

前端 `Vue/src/views/` 对应页面：登录/注册、仪表盘、主动扫描、被动扫描、组合扫描、DNSLog、XSS、监控、邮件、木马 Shellcode、个人信息设置等。

## 文档

- 使用文档：<http://medusa.ascotbe.com>
- 安装说明：<https://medusa.ascotbe.com/Documentation/#/Installation>
- 更新日志：<http://medusa.ascotbe.com/Documentation/#/UpDataLog>
- API 文档（`docs/Documentation/API/`）：主动扫描、被动扫描、应用收集、CVE、XSS、DNSLog、邮件、文件获取、监控、工具、木马、用户等模块均有独立说明。

## Web 界面

![demo](https://github.com/Ascotbe/Image/blob/master/Medusa/web_demo.gif?raw=true)

## 安装与启动

### 手动安装

```bash
git clone https://github.com/Ascotbe/Medusa.git
cd Medusa
pip install -r Medusa.txt      # 后端依赖（Python 3.7+）
cd Vue && npm install          # 前端依赖（Node.js 12.x–14.x，推荐 14 LTS，对应 Vue CLI 4.5）
```

后端配置见 `config.py`（标注 `必须修改` 的字段需填写），前端配置见 `Vue/faceConfig.js`，详细步骤见 `docs/Documentation/Installation.md`。

完整启动（根目录）：

```bash
python3 DNSServer.py &        # DNSLog 服务（端口 8888）
python3 HTTPServer.py &       # HTTP 服务（端口 9999）
celery -A Web worker -B --loglevel=info --pool=solo &
gunicorn Web.wsgi:application --bind 0.0.0.0:9999 --workers 6
```

### Docker 安装

```bash
git clone https://github.com/Ascotbe/Medusa.git
cd Medusa
sudo chmod +x install.sh
./install.sh -u medusa.test.ascotbe.com -d dnslog.test.ascotbe.com -s ascotbe.com
```

参数说明：`-u` Web 端域名（必填）、`-d` DNSLog 接收域名（必填）、`-s` 自建 SMTP 服务器域名（邮箱 @ 后的值）。Docker 部署最低需 1 核 2G。

## 提交意见

- 发现插件扫描不到对应漏洞：提交 `[Bug]` 类 issue
- 文档无法解决的问题：提交 `[help]` 类 issue
- 好的意见或想法：提交 `[idea]` 类 issue

## 免责声明

本项目衍生自 [Ascotbe/Medusa](https://github.com/Ascotbe/Medusa)，在原有[协议](https://github.com/Ascotbe/Medusa/blob/master/LICENSE)基础上追加以下内容：

- 本项目禁止进行未授权商业用途
- 本项目禁止二次开发后进行商业用途
- 本项目仅面向**合法授权**的企业安全建设行为，在使用本项目进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。
- 如您在使用本项目的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
- 在使用本项目前，请您**务必审慎阅读、充分理解各条款内容**，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本项目。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。

