# Update 2026-11-18
## CVE-2026-129494
 CloudPaste 1.1.0 through 1.9.1 contains an information disclosure vulnerability that allows unauthenticated attackers to obtain WebDAV storage credentials through the unauthenticated /api/proxy/link endpoint. Attackers who know a public share slug can retrieve the Basic Authorization header containing the WebDAV username and password, then read, modify, or delete files on the WebDAV server.

- [https://github.com/googlesky/CVE-2026-129494](https://github.com/googlesky/CVE-2026-129494) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129494.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129494.svg)


## CVE-2026-129493
 Bolo (bolo-solo) 1.7 through 2.6.4 contains an information disclosure vulnerability that allows unauthenticated attackers to read article view passwords via the public GET /articles endpoint. Attackers can retrieve the plaintext articleViewPwd field returned by ArticleProcessor.getArticlesByPage and submit it to read password-protected article content.

- [https://github.com/googlesky/CVE-2026-129493](https://github.com/googlesky/CVE-2026-129493) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129493.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129493.svg)


## CVE-2026-129492
 Bolo (bolo-solo) 1.7 through 2.6.4 contains a stored cross-site scripting vulnerability that allows unauthenticated attackers to inject scripts via the unsanitized commentOriginalCommentName parameter. Attackers can post a comment to /article/comments with a short payload that steals non-HttpOnly session cookies from visitors, enabling takeover of administrator accounts.

- [https://github.com/googlesky/CVE-2026-129492](https://github.com/googlesky/CVE-2026-129492) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129492.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129492.svg)


## CVE-2026-129491
 Qbian61 forum-java commit 20f7e68 through commit 63152c4 contains a stored cross-site scripting vulnerability that allows authenticated users to inject script by posting unsanitized comment content rendered via jQuery .html() in the reply dialog. Attackers can post comments with img onerror payloads that execute when victims click Reply, stealing the non-HttpOnly sid session cookie to hijack accounts including administrators.

- [https://github.com/googlesky/CVE-2026-129491](https://github.com/googlesky/CVE-2026-129491) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129491.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129491.svg)


## CVE-2026-129358
 A vulnerability was identified in Linux Foundation Magma up to 1.9.0. Impacted is the function handleReact of the file nms/server/main/routes.ts of the component NMS. Such manipulation leads to cross site scripting. It is possible to launch the attack remotely. The exploit is publicly available and might be used. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/googlesky/CVE-2026-129358](https://github.com/googlesky/CVE-2026-129358) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129358.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129358.svg)


## CVE-2026-129357
 A vulnerability was determined in Linux Foundation Magma up to 1.9.0. This issue affects the function hostOrgMiddleware of the file nms/server/host/middleware.ts of the component Host Middleware. This manipulation of the argument role causes missing authorization. It is possible to initiate the attack remotely. The exploit has been publicly disclosed and may be utilized. The vendor was contacted early about this disclosure but did not respond in any way.

- [https://github.com/googlesky/CVE-2026-129357](https://github.com/googlesky/CVE-2026-129357) :  ![starts](https://img.shields.io/github/stars/googlesky/CVE-2026-129357.svg) ![forks](https://img.shields.io/github/forks/googlesky/CVE-2026-129357.svg)


## CVE-2026-126170
 A improper encoding or escaping of output vulnerability in Fortinet FortiAnalyzer 8.0.0 through 8.0.2, FortiAnalyzer 7.6.0 through 7.6.7, FortiAnalyzer Cloud 8.0.1 through 8.0.2, FortiAnalyzer Cloud 7.6.0 through 7.6.7, FortiAnalyzer-BigData 7.6.0 through 7.6.2, FortiManager 8.0.0 through 8.0.2, FortiManager 7.6.0 through 7.6.7, FortiManager Cloud 8.0.1 through 8.0.2, FortiManager Cloud 7.6.0 through 7.6.7 may allow an unauthenticated attacker to execute unauthorized code or commands via a specially crafted HTTP request

- [https://github.com/Ghost-Bx1/fortinet-exploits](https://github.com/Ghost-Bx1/fortinet-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/fortinet-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/fortinet-exploits.svg)
- [https://github.com/im-hanzou/cve-2026-126170-fortimanager-jsonrpc-rce](https://github.com/im-hanzou/cve-2026-126170-fortimanager-jsonrpc-rce) :  ![starts](https://img.shields.io/github/stars/im-hanzou/cve-2026-126170-fortimanager-jsonrpc-rce.svg) ![forks](https://img.shields.io/github/forks/im-hanzou/cve-2026-126170-fortimanager-jsonrpc-rce.svg)


## CVE-2026-125423
 A repository created with auto-init accepted pushes before its initialization had finished, and the initial commit was built in a checkout of whatever the repository already contained. A user who is allowed to create repositories could push a crafted tree during that window so that writing the README followed a symbolic link and overwrote a server-side git hook, which runs commands as the Gitea system user. The initial commit is now built in a freshly initialized directory, and a new repository only becomes ready, and accepts pushes, once its initialization is complete.

- [https://github.com/grigorovichvlad/CVE-2026-125423](https://github.com/grigorovichvlad/CVE-2026-125423) :  ![starts](https://img.shields.io/github/stars/grigorovichvlad/CVE-2026-125423.svg) ![forks](https://img.shields.io/github/forks/grigorovichvlad/CVE-2026-125423.svg)


## CVE-2026-124020
 Control Web Panel (CWP) before webpanel_version 1.30.6 contains a host header injection vulnerability that allows unauthenticated attackers to manipulate the password-recovery reset URL by injecting the HTTP Host header into the /v1/lostpass/ route's token generation process. Attackers can lure an automated mail-security scanner into visiting the poisoned reset link to exfiltrate the live recovery token, replay it at /login/index.php?acc=newpass to set a new password, and subsequently abuse the File Manager and Crontab modules to achieve command execution as the targeted hosting account.

- [https://github.com/LLCForge/CVE-2026-124020](https://github.com/LLCForge/CVE-2026-124020) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-124020.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-124020.svg)


## CVE-2026-123158
 sshd in OpenSSH before 10.6p2 on Linux, when musl libc is used without PAM, lacks a workaround for a password authentication bypass (related to misinterpretation of whether a string is intended to be a password hash). For some configurations of accounts, any password between 256 and 1024 characters succeeds. An example of a platform using musl libc without PAM is Alpine Linux.

- [https://github.com/LaMambaKukun/Hack-The-Box-Sherlock-SSHole-](https://github.com/LaMambaKukun/Hack-The-Box-Sherlock-SSHole-) :  ![starts](https://img.shields.io/github/stars/LaMambaKukun/Hack-The-Box-Sherlock-SSHole-.svg) ![forks](https://img.shields.io/github/forks/LaMambaKukun/Hack-The-Box-Sherlock-SSHole-.svg)
- [https://github.com/diallocode/SSHOLE-POC](https://github.com/diallocode/SSHOLE-POC) :  ![starts](https://img.shields.io/github/stars/diallocode/SSHOLE-POC.svg) ![forks](https://img.shields.io/github/forks/diallocode/SSHOLE-POC.svg)


## CVE-2026-123039
 The Gaia OS DynamicCLI daemon runs as root and listens on a world-writable local socket (/tmp/dynamic_socket) without authenticating connecting processes. An authenticated local user can send a command to the socket and have it executed as root.

- [https://github.com/foxcornlab/checkpoint-gaia-scanner](https://github.com/foxcornlab/checkpoint-gaia-scanner) :  ![starts](https://img.shields.io/github/stars/foxcornlab/checkpoint-gaia-scanner.svg) ![forks](https://img.shields.io/github/forks/foxcornlab/checkpoint-gaia-scanner.svg)


## CVE-2026-121529
 A origin validation error vulnerability in Fortinet FortiClientMac 7.4.0 through 7.4.7, FortiClientWindows 7.4.0 through 7.4.7, FortiClientWindows 7.2.0 through 7.2.14, FortiClientWindowsPAM 7.4.7, FortiClientWindowsPAM 7.2.14 may allow an unauthorized remote attacker to execute unauthorized code or commands. Successful exploitation requires interaction with the victim.

- [https://github.com/Ghost-Bx1/fortinet-exploits](https://github.com/Ghost-Bx1/fortinet-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/fortinet-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/fortinet-exploits.svg)


## CVE-2026-119618
Affected releases of mod_h2 from GitHub: from 2.0.8 through 2.0.42.

- [https://github.com/Doseuser/CVE-2026-119618---RCE-in-APACHE](https://github.com/Doseuser/CVE-2026-119618---RCE-in-APACHE) :  ![starts](https://img.shields.io/github/stars/Doseuser/CVE-2026-119618---RCE-in-APACHE.svg) ![forks](https://img.shields.io/github/forks/Doseuser/CVE-2026-119618---RCE-in-APACHE.svg)
- [https://github.com/dansaurabh/h2race-check_CVE-2026-119618](https://github.com/dansaurabh/h2race-check_CVE-2026-119618) :  ![starts](https://img.shields.io/github/stars/dansaurabh/h2race-check_CVE-2026-119618.svg) ![forks](https://img.shields.io/github/forks/dansaurabh/h2race-check_CVE-2026-119618.svg)


## CVE-2026-119258
 The Swipe WordPress plugin through 1.4 does not properly authenticate a login request before issuing a WordPress session cookie, allowing unauthenticated attackers to log in as an existing user, including an administrator, when that user has an active app session.

- [https://github.com/LLCForge/CVE-2026-119258](https://github.com/LLCForge/CVE-2026-119258) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-119258.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-119258.svg)


## CVE-2026-119179
 A flaw in the connection management layer of the MongoDB Node.js driver can leave a pooled network connection in the pool for reuse while data from an earlier operation is still outstanding on it. In applications that enable an optional client-side operation timeout, an unauthenticated party that can send ordinary requests to the application may cause database replies to be paired with the wrong requests. This may result in unintended disclosure of other users' records, incorrect operation results being returned, and failures of legitimate requests.

- [https://github.com/LLCForge/CVE-2026-119179](https://github.com/LLCForge/CVE-2026-119179) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-119179.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-119179.svg)


## CVE-2026-118755
 Volmarg Personal Management System through 2.1.0 contains an OS command injection vulnerability that allows authenticated users to execute shell commands via unescaped folder paths in the storage module's tree command. Attackers can create a directory under upload/files containing shell metacharacters such as $(...) and then move or copy it, running commands as the web server user.

- [https://github.com/0xDracarys/CVE-Writeups](https://github.com/0xDracarys/CVE-Writeups) :  ![starts](https://img.shields.io/github/stars/0xDracarys/CVE-Writeups.svg) ![forks](https://img.shields.io/github/forks/0xDracarys/CVE-Writeups.svg)


## CVE-2026-117551
 Joomla Extension - jdownloads.com - RCE through file upload in jDownloads  4.1.8 -  Insufficient validation of frontend thumbnail uploads allowed users with upload permission to place executable files on the server. This results in PHP code execution.

- [https://github.com/Fad-X/CVE-20260-117551](https://github.com/Fad-X/CVE-20260-117551) :  ![starts](https://img.shields.io/github/stars/Fad-X/CVE-20260-117551.svg) ![forks](https://img.shields.io/github/forks/Fad-X/CVE-20260-117551.svg)


## CVE-2026-116779
 FreeSWITCH is a Software Defined Telecom Stack enabling the digital transformation from proprietary telecom switches to a software implementation that runs on any commodity hardware. Prior to 1.11.3, sofia_presence_handle_sip_i_message() split the To user of an inbound SIP MESSAGE on a plus sign and treated the left side as a chat protocol selector. Selecting the api chat proto reached switch_api_execute(), allowing a peer whose MESSAGE was accepted to run FreeSWITCH API commands, including operating-system command sinks, with the daemon's privileges. Inbound chat is enabled on the stock internal and external profiles, and any authenticated profile account is sufficient; stock directory users without password material can also remove that barrier in affected configurations. The flaw permits configuration and credential disclosure, arbitrary call control, and command execution, and exploitation has been observed in the wild. This issue is fixed in version 1.11.3.

- [https://github.com/ashrafzaryouh/CVE-2026-116779](https://github.com/ashrafzaryouh/CVE-2026-116779) :  ![starts](https://img.shields.io/github/stars/ashrafzaryouh/CVE-2026-116779.svg) ![forks](https://img.shields.io/github/forks/ashrafzaryouh/CVE-2026-116779.svg)
- [https://github.com/pentestershell/CVE-2026-116779](https://github.com/pentestershell/CVE-2026-116779) :  ![starts](https://img.shields.io/github/stars/pentestershell/CVE-2026-116779.svg) ![forks](https://img.shields.io/github/forks/pentestershell/CVE-2026-116779.svg)


## CVE-2026-116492
 Frappe CRM app before 1.89.1 contains a missing authorization vulnerability that allows authenticated low-privileged users to read CRM Lead records they are not permitted to access by querying the get_contact_by_phone_number API, which performs raw database queries without invoking the permission system. Attackers can supply a known phone number to the crm.integrations.api.get_contact_by_phone_number endpoint to retrieve full lead details otherwise blocked by standard API and UI access controls, resulting in unauthorized disclosure of sensitive CRM data.

- [https://github.com/0xDracarys/CVE-Writeups](https://github.com/0xDracarys/CVE-Writeups) :  ![starts](https://img.shields.io/github/stars/0xDracarys/CVE-Writeups.svg) ![forks](https://img.shields.io/github/forks/0xDracarys/CVE-Writeups.svg)


## CVE-2026-116331
 Type confusion in PostgreSQL min/max aggregate optimization allows an object creator to execute arbitrary code as the operating system user running the database, via a user-defined aggregate whose SORTOP option causes the planner to treat the aggregate's input and result as the same type when they differ.  Versions before PostgreSQL 18.7, 17.12, 16.16, 15.20, and 14.25 are affected.

- [https://github.com/notdenied/CVE-2026-116331-PoC](https://github.com/notdenied/CVE-2026-116331-PoC) :  ![starts](https://img.shields.io/github/stars/notdenied/CVE-2026-116331-PoC.svg) ![forks](https://img.shields.io/github/forks/notdenied/CVE-2026-116331-PoC.svg)


## CVE-2026-112706
 A permissions issue was addressed with additional restrictions. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, tvOS 27.2, visionOS 27.2, watchOS 27.2. An app may be able to access sensitive user data.

- [https://github.com/794pn2s6fh-hub/CVE-2026-112706-apple-watch](https://github.com/794pn2s6fh-hub/CVE-2026-112706-apple-watch) :  ![starts](https://img.shields.io/github/stars/794pn2s6fh-hub/CVE-2026-112706-apple-watch.svg) ![forks](https://img.shields.io/github/forks/794pn2s6fh-hub/CVE-2026-112706-apple-watch.svg)


## CVE-2026-112611
 An out-of-bounds write issue was addressed with improved bounds checking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2. Processing a maliciously crafted PDF file may lead to memory corruption.

- [https://github.com/marksvia/CVE-2026-112611-oob](https://github.com/marksvia/CVE-2026-112611-oob) :  ![starts](https://img.shields.io/github/stars/marksvia/CVE-2026-112611-oob.svg) ![forks](https://img.shields.io/github/forks/marksvia/CVE-2026-112611-oob.svg)


## CVE-2026-112477
 A race condition was addressed with improved locking. This issue is fixed in iOS 26.7.2 and iPadOS 26.7.2, iOS 27.2 and iPadOS 27.2, macOS Golden Gate 27.2, macOS Sequoia 15.8.2, macOS Tahoe 26.7.2, tvOS 27.2, visionOS 27.2, watchOS 27.2. An app may be able to cause unexpected system termination or corrupt kernel memory.

- [https://github.com/Sparticle62ops/israce-probe](https://github.com/Sparticle62ops/israce-probe) :  ![starts](https://img.shields.io/github/stars/Sparticle62ops/israce-probe.svg) ![forks](https://img.shields.io/github/forks/Sparticle62ops/israce-probe.svg)


## CVE-2026-112182
 Unauthorization vulnerability in the management of workflow definitions in OpenKM Community Edition. The REST endpoints `registerProcessDefinition` and `runProcessDefinition` require authentication but do not verify roles in the WorkflowService or in lower layers. An attacker with the `ROLE_USER` role can register and execute a process definition containing BeanShell scripts, allowing them to execute Java code and operating system commands with the service’s privileges. In the official Docker image, the process runs as root.

- [https://github.com/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce](https://github.com/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce) :  ![starts](https://img.shields.io/github/stars/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce.svg) ![forks](https://img.shields.io/github/forks/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce.svg)


## CVE-2026-112181
 Vulnerability due to inadequate restriction of references to external XML entities in OpenKM Community Edition. The XML processing in FormUtils / LocalEntityResolver does not properly restrict the resolution of external resources. An authenticated remote attacker with the ROLE_USER role can exploit the flaw via a REST request. In the 6.3.x branch, this allows the attacker to trigger HTTP requests under their control (SSRF); in 7.0.3, it allows the attacker to read local files and access internal HTTP resources from the server.

- [https://github.com/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce](https://github.com/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce) :  ![starts](https://img.shields.io/github/stars/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce.svg) ![forks](https://img.shields.io/github/forks/Lasersinho/cve-2026-112181-cve-2026-112182-openkm-ce.svg)


## CVE-2026-111760
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. Prior to 2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1, and 2.56.1, an attacker-controlled repository hosted by the attacker rather than on a normal forge site can exploit git clone --recurse-submodules by causing Git to overwrite a submodule gitfile with a symbolic link. The symbolic link can point to a directory containing attacker-controlled Git configuration or hooks, allowing those hooks or configuration to execute code on the cloning user's system. The issue requires the recursive-submodule option, and users should avoid cloning repositories from untrusted sources. This issue is fixed in versions 2.50.2, 2.51.3, 2.52.1, 2.53.1, 2.54.1, 2.55.1, and 2.56.1.

- [https://github.com/jayeshpuri/CVE-2026-111760](https://github.com/jayeshpuri/CVE-2026-111760) :  ![starts](https://img.shields.io/github/stars/jayeshpuri/CVE-2026-111760.svg) ![forks](https://img.shields.io/github/forks/jayeshpuri/CVE-2026-111760.svg)
- [https://github.com/suominen/CVE-2026-111760](https://github.com/suominen/CVE-2026-111760) :  ![starts](https://img.shields.io/github/stars/suominen/CVE-2026-111760.svg) ![forks](https://img.shields.io/github/forks/suominen/CVE-2026-111760.svg)
- [https://github.com/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce](https://github.com/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/cve-2026-111760-git-submodule-symlink-rce.svg)
- [https://github.com/SSJCorpSec/cve-2026-111760-40b639e0](https://github.com/SSJCorpSec/cve-2026-111760-40b639e0) :  ![starts](https://img.shields.io/github/stars/SSJCorpSec/cve-2026-111760-40b639e0.svg) ![forks](https://img.shields.io/github/forks/SSJCorpSec/cve-2026-111760-40b639e0.svg)
- [https://github.com/SSJCorpSec/cve-2026-111760-b3-85967fc9](https://github.com/SSJCorpSec/cve-2026-111760-b3-85967fc9) :  ![starts](https://img.shields.io/github/stars/SSJCorpSec/cve-2026-111760-b3-85967fc9.svg) ![forks](https://img.shields.io/github/forks/SSJCorpSec/cve-2026-111760-b3-85967fc9.svg)


## CVE-2026-111559
The project is no longer maintained and the issue has not been fixed.

- [https://github.com/Tymbark7372/CVE-2026-111559](https://github.com/Tymbark7372/CVE-2026-111559) :  ![starts](https://img.shields.io/github/stars/Tymbark7372/CVE-2026-111559.svg) ![forks](https://img.shields.io/github/forks/Tymbark7372/CVE-2026-111559.svg)


## CVE-2026-111497
Users need to update any Brotli libraries or binaries between 1.0.3 through 1.2.0 to the latest available version: 1.0.10 or 1.1.1 or 1.2.1.

- [https://github.com/TimmyTurner51/brotli-lab](https://github.com/TimmyTurner51/brotli-lab) :  ![starts](https://img.shields.io/github/stars/TimmyTurner51/brotli-lab.svg) ![forks](https://img.shields.io/github/forks/TimmyTurner51/brotli-lab.svg)
- [https://github.com/csakala-art/cbci-libbrotli-patch-25551](https://github.com/csakala-art/cbci-libbrotli-patch-25551) :  ![starts](https://img.shields.io/github/stars/csakala-art/cbci-libbrotli-patch-25551.svg) ![forks](https://img.shields.io/github/forks/csakala-art/cbci-libbrotli-patch-25551.svg)


## CVE-2026-110960
 The Auth Armor  WordPress plugin through 1.0.3 does not require authentication on several handlers available to logged-out users, which leak the site's stored API credentials and allow an unauthenticated attacker to reset an administrator's enrollment and take over that administrator account.

- [https://github.com/LLCForge/CVE-2026-110960](https://github.com/LLCForge/CVE-2026-110960) :  ![starts](https://img.shields.io/github/stars/LLCForge/CVE-2026-110960.svg) ![forks](https://img.shields.io/github/forks/LLCForge/CVE-2026-110960.svg)


## CVE-2026-109619
 PHP has various global state that temporarily points into request memory. In some scenarios, global state may not be correctly reset, or may be repopulated after being reset. The global state may then refer to request memory even after it has been freed. Subsequent requests may read or branch on this stale state before it is fully initialized. Multiple strategies can trigger this condition and produce remote code execution (RCE).

- [https://github.com/k1shlabs/PHP2Shell-Detection-with-Wazuh](https://github.com/k1shlabs/PHP2Shell-Detection-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/PHP2Shell-Detection-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/PHP2Shell-Detection-with-Wazuh.svg)
- [https://github.com/mehmet-emir-eroglu/PHP2SHELL](https://github.com/mehmet-emir-eroglu/PHP2SHELL) :  ![starts](https://img.shields.io/github/stars/mehmet-emir-eroglu/PHP2SHELL.svg) ![forks](https://img.shields.io/github/forks/mehmet-emir-eroglu/PHP2SHELL.svg)


## CVE-2026-109618
 PHP uses longjmp() for out-of-memory (OOM) errors to exit the current context and abort handling of the request. Some contexts may not properly account for this scenario and leave request memory in an uninitialized state before performing an allocation. The subsequent request cleanup procedure may read or branch on this memory. Multiple OOM strategies can consistently trigger this condition and lead to remote code execution (RCE).

- [https://github.com/k1shlabs/PHP2Shell-Detection-with-Wazuh](https://github.com/k1shlabs/PHP2Shell-Detection-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/PHP2Shell-Detection-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/PHP2Shell-Detection-with-Wazuh.svg)
- [https://github.com/RedSideSecurity/php2shell](https://github.com/RedSideSecurity/php2shell) :  ![starts](https://img.shields.io/github/stars/RedSideSecurity/php2shell.svg) ![forks](https://img.shields.io/github/forks/RedSideSecurity/php2shell.svg)


## CVE-2026-107656
 An authentication bypass using an alternate path or channel vulnerability in Fortinet FortiSandbox 5.0.0 through 5.0.6, FortiSandbox 4.4.0 through 4.4.9, FortiSandbox 4.2 all versions, FortiSandbox PaaS 5.0.0 through 5.0.6, FortiSandbox PaaS 4.4 all versions, FortiSandbox PaaS 4.2 all versions may allow attacker to execute unauthorized code or commands via crafted HTTP requests

- [https://github.com/Ghost-Bx1/fortinet-exploits](https://github.com/Ghost-Bx1/fortinet-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/fortinet-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/fortinet-exploits.svg)
- [https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-106173
 A improper limitation of a pathname to a restricted directory ('path traversal') vulnerability in Fortinet FortiSIEM 7.5.0, FortiSIEM 7.4 all versions, FortiSIEM 7.3 all versions, FortiSIEM 7.2 all versions, FortiSIEM 7.1 all versions, FortiSIEM 7.0 all versions may allow attacker to execute unauthorized code or commands via specially crafted packets.

- [https://github.com/Ghost-Bx1/fortinet-exploits](https://github.com/Ghost-Bx1/fortinet-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/fortinet-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/fortinet-exploits.svg)
- [https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-99288
with reqsk_put() instead of freeing the request directly.

- [https://github.com/h0rn3t/noisytcp-lab](https://github.com/h0rn3t/noisytcp-lab) :  ![starts](https://img.shields.io/github/stars/h0rn3t/noisytcp-lab.svg) ![forks](https://img.shields.io/github/forks/h0rn3t/noisytcp-lab.svg)
- [https://github.com/tal7aouy/NoisyTCP](https://github.com/tal7aouy/NoisyTCP) :  ![starts](https://img.shields.io/github/stars/tal7aouy/NoisyTCP.svg) ![forks](https://img.shields.io/github/forks/tal7aouy/NoisyTCP.svg)


## CVE-2026-98260
[ tglx: Move the cleanup right after de_thread() ]

- [https://github.com/aoxzh/cve-2026-98260-vivo-x200-ultra-temproot](https://github.com/aoxzh/cve-2026-98260-vivo-x200-ultra-temproot) :  ![starts](https://img.shields.io/github/stars/aoxzh/cve-2026-98260-vivo-x200-ultra-temproot.svg) ![forks](https://img.shields.io/github/forks/aoxzh/cve-2026-98260-vivo-x200-ultra-temproot.svg)
- [https://github.com/idk12345-desigh/lapis-mt6878-root](https://github.com/idk12345-desigh/lapis-mt6878-root) :  ![starts](https://img.shields.io/github/stars/idk12345-desigh/lapis-mt6878-root.svg) ![forks](https://img.shields.io/github/forks/idk12345-desigh/lapis-mt6878-root.svg)
- [https://github.com/mumaosong/cve-2026-98260-app](https://github.com/mumaosong/cve-2026-98260-app) :  ![starts](https://img.shields.io/github/stars/mumaosong/cve-2026-98260-app.svg) ![forks](https://img.shields.io/github/forks/mumaosong/cve-2026-98260-app.svg)
- [https://github.com/Yunxi422/CVE-2026-98260-OPD2405](https://github.com/Yunxi422/CVE-2026-98260-OPD2405) :  ![starts](https://img.shields.io/github/stars/Yunxi422/CVE-2026-98260-OPD2405.svg) ![forks](https://img.shields.io/github/forks/Yunxi422/CVE-2026-98260-OPD2405.svg)
- [https://github.com/aoxzh/cve-2026-98260-tb710fu](https://github.com/aoxzh/cve-2026-98260-tb710fu) :  ![starts](https://img.shields.io/github/stars/aoxzh/cve-2026-98260-tb710fu.svg) ![forks](https://img.shields.io/github/forks/aoxzh/cve-2026-98260-tb710fu.svg)


## CVE-2026-95518
This issue affects Pardus Package Installer: from 0.7.0 before 0.7.1.

- [https://github.com/ozcanpng/CVE-2026-95518](https://github.com/ozcanpng/CVE-2026-95518) :  ![starts](https://img.shields.io/github/stars/ozcanpng/CVE-2026-95518.svg) ![forks](https://img.shields.io/github/forks/ozcanpng/CVE-2026-95518.svg)


## CVE-2026-83549
 Post-authentication Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability has been identified in the SMA1000 Appliance Management Console (AMC) which in specific conditions could potentially enable a remote authenticated attacker as administrator to execute arbitrary OS commands, resulting in remote code execution.

- [https://github.com/0xTerror/CVE-2026-83548-CVE-2026-83549](https://github.com/0xTerror/CVE-2026-83548-CVE-2026-83549) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2026-83548-CVE-2026-83549.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2026-83548-CVE-2026-83549.svg)


## CVE-2026-83548
 A Pre-authentication SSRF vulnerability exists in the SMA1000 Appliance Work Place interface due to an unintended alternate access path. A remote unauthenticated attacker could potentially exploit this vulnerability to gain unauthorized access to sensitive functionality and perform unauthorized operations.

- [https://github.com/0xTerror/CVE-2026-83548-CVE-2026-83549](https://github.com/0xTerror/CVE-2026-83548-CVE-2026-83549) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2026-83548-CVE-2026-83549.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2026-83548-CVE-2026-83549.svg)


## CVE-2026-81963
 Improper link resolution before file access ('link following') in Windows Update Stack allows an authorized attacker to elevate privileges locally.

- [https://github.com/nithishgupta-cys/CVE-2026-81963-TrustedDpx](https://github.com/nithishgupta-cys/CVE-2026-81963-TrustedDpx) :  ![starts](https://img.shields.io/github/stars/nithishgupta-cys/CVE-2026-81963-TrustedDpx.svg) ![forks](https://img.shields.io/github/forks/nithishgupta-cys/CVE-2026-81963-TrustedDpx.svg)


## CVE-2026-81000
other allocation paths.

- [https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-80844
errors to the existing AH6 input and output error paths.

- [https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-78287
 Improper Control of Generation of Code ('Code Injection') vulnerability in Staggs STAGGS staggs allows Remote Code Inclusion.This issue affects STAGGS: from n/a through 3.3.0.

- [https://github.com/0xTerror/CVE-2026-78287](https://github.com/0xTerror/CVE-2026-78287) :  ![starts](https://img.shields.io/github/stars/0xTerror/CVE-2026-78287.svg) ![forks](https://img.shields.io/github/forks/0xTerror/CVE-2026-78287.svg)


## CVE-2026-74469
to return its existing transport at the limit.

- [https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-68121
relocates the head.

- [https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh](https://github.com/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh) :  ![starts](https://img.shields.io/github/stars/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/Detect-Quartet-of-Linux-local-root-vulns-with-Wazuh.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4](https://github.com/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/DIRTY-FRAG-Detection-with-Wazuh-4.14.4.svg)


## CVE-2026-43074
Defer the kfree() to an RCU callback to prevent UAF.

- [https://github.com/ngtuonghung/CVE-2026-43074](https://github.com/ngtuonghung/CVE-2026-43074) :  ![starts](https://img.shields.io/github/stars/ngtuonghung/CVE-2026-43074.svg) ![forks](https://img.shields.io/github/forks/ngtuonghung/CVE-2026-43074.svg)


## CVE-2026-39808
 A improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSandbox 4.4.0 through 4.4.8 may allow attacker to execute unauthorized code or commands via insert attack vector here

- [https://github.com/Ghost-Bx1/fortinet-exploits](https://github.com/Ghost-Bx1/fortinet-exploits) :  ![starts](https://img.shields.io/github/stars/Ghost-Bx1/fortinet-exploits.svg) ![forks](https://img.shields.io/github/forks/Ghost-Bx1/fortinet-exploits.svg)
- [https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656](https://github.com/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656) :  ![starts](https://img.shields.io/github/stars/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg) ![forks](https://img.shields.io/github/forks/joel-correa/Fortinet-Exploits-CVE-2026-39808-106173-107656.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/k1shlabs/COPY-FAIL-Detection-with-Wazuh-4.14.4](https://github.com/k1shlabs/COPY-FAIL-Detection-with-Wazuh-4.14.4) :  ![starts](https://img.shields.io/github/stars/k1shlabs/COPY-FAIL-Detection-with-Wazuh-4.14.4.svg) ![forks](https://img.shields.io/github/forks/k1shlabs/COPY-FAIL-Detection-with-Wazuh-4.14.4.svg)


## CVE-2026-25863
 Conditional Fields for Contact Form 7 WordPress plugin through version 2.7.2 contains an uncontrolled resource consumption vulnerability in the Wpcf7cfMailParser class where the hide_hidden_mail_fields_regex_callback() method reads an iteration count directly from user-supplied POST parameters without validation or upper bound enforcement. Unauthenticated attackers can supply an arbitrarily large integer value through the REST API endpoint to cause unbounded loop execution with multiple preg_replace() operations, exhausting server memory and crashing the PHP process.

- [https://github.com/rahulreddykarne/ARK-WP-Scanner](https://github.com/rahulreddykarne/ARK-WP-Scanner) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/ARK-WP-Scanner.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/ARK-WP-Scanner.svg)


## CVE-2026-23694
 Aruba HiSpeed Cache (aruba-hispeed-cache) WordPress plugin versions prior to 3.0.5 contain a cross-site request forgery (CSRF) vulnerability affecting multiple administrative AJAX actions. The handlers for ahsc_reset_options, ahsc_debug_status, and ahsc_enable_purge perform authentication and capability checks but do not verify a WordPress nonce for state-changing requests. An attacker can induce a logged-in administrator to visit a malicious webpage that submits forged requests to admin-ajax.php, resulting in unauthorized resetting of plugin settings, toggling of the WordPress WP_DEBUG configuration, or modification of cache purging behavior without the administrator’s intent.

- [https://github.com/rahulreddykarne/ARK-WP-Scanner](https://github.com/rahulreddykarne/ARK-WP-Scanner) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/ARK-WP-Scanner.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/ARK-WP-Scanner.svg)


## CVE-2026-23693
 ElementsKit Elementor Addons – Advanced Widgets & Templates Addons for Elementor (elementskit-lite) WordPress plugin versions prior to 3.7.9 expose the REST endpoint /wp-json/elementskit/v1/widget/mailchimp/subscribe without authentication. The endpoint accepts client-supplied Mailchimp API credentials and insufficiently validates certain parameters, including the list parameter, when constructing upstream Mailchimp API requests. An unauthenticated attacker can abuse the endpoint as an open proxy to Mailchimp, potentially triggering unauthorized API calls, manipulating subscription data, exhausting API quotas, or causing resource consumption on the affected WordPress site.

- [https://github.com/rahulreddykarne/ARK-WP-Scanner](https://github.com/rahulreddykarne/ARK-WP-Scanner) :  ![starts](https://img.shields.io/github/stars/rahulreddykarne/ARK-WP-Scanner.svg) ![forks](https://img.shields.io/github/forks/rahulreddykarne/ARK-WP-Scanner.svg)


## CVE-2026-21155
 Out-of-bounds write in bootloader prior to SMR Nov-2026 Release 1 allows physical attackers to write out-of-bounds memory.

- [https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546](https://github.com/UnsignedChad/CVE-2026-21155-SVE-2026-3546) :  ![starts](https://img.shields.io/github/stars/UnsignedChad/CVE-2026-21155-SVE-2026-3546.svg) ![forks](https://img.shields.io/github/forks/UnsignedChad/CVE-2026-21155-SVE-2026-3546.svg)
- [https://github.com/yuki493/s5e8835-sboot-probe](https://github.com/yuki493/s5e8835-sboot-probe) :  ![starts](https://img.shields.io/github/stars/yuki493/s5e8835-sboot-probe.svg) ![forks](https://img.shields.io/github/forks/yuki493/s5e8835-sboot-probe.svg)


## CVE-2026-16723
 A remote code execution (RCE) vulnerability exists in fastjson 1.2.68 through 1.2.83. This vulnerability is exploitable under fastjson's stock default configuration — no AutoType enablement required, no classpath gadget required.

- [https://github.com/punksitr-sys/CVE-2026-16723](https://github.com/punksitr-sys/CVE-2026-16723) :  ![starts](https://img.shields.io/github/stars/punksitr-sys/CVE-2026-16723.svg) ![forks](https://img.shields.io/github/forks/punksitr-sys/CVE-2026-16723.svg)


## CVE-2026-15315
condition.

- [https://github.com/moyaiix/Tapo-CVE-2026-15315-Poc](https://github.com/moyaiix/Tapo-CVE-2026-15315-Poc) :  ![starts](https://img.shields.io/github/stars/moyaiix/Tapo-CVE-2026-15315-Poc.svg) ![forks](https://img.shields.io/github/forks/moyaiix/Tapo-CVE-2026-15315-Poc.svg)


## CVE-2026-14431
 Type Confusion in V8 in Google Chrome prior to 150.0.7871.46 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/jaf0rk/CVE-2026-14431](https://github.com/jaf0rk/CVE-2026-14431) :  ![starts](https://img.shields.io/github/stars/jaf0rk/CVE-2026-14431.svg) ![forks](https://img.shields.io/github/forks/jaf0rk/CVE-2026-14431.svg)


## CVE-2026-10961
 Use after free in Chrome for iOS in Google Chrome on iOS prior to 149.0.7827.53 allowed a remote attacker who had compromised the renderer process to potentially perform a sandbox escape via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618](https://github.com/cloudducoeur/ansible-playbook-CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/cloudducoeur/ansible-playbook-CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/cloudducoeur/ansible-playbook-CVE-2026-109618.svg)


## CVE-2026-9999
 Inappropriate implementation in ANGLE in Google Chrome on Mac prior to 148.0.7778.216 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/Hazem777-G/CVE-2026-9999-PoC](https://github.com/Hazem777-G/CVE-2026-9999-PoC) :  ![starts](https://img.shields.io/github/stars/Hazem777-G/CVE-2026-9999-PoC.svg) ![forks](https://img.shields.io/github/forks/Hazem777-G/CVE-2026-9999-PoC.svg)


## CVE-2026-3650
 A memory leak exists in the Grassroots DICOM library (GDCM). The bug occurs when parsing malformed DICOM files with non-standard VR types in file meta information. The vulnerability leads to vast memory allocations and resource depletion, triggering a denial-of-service condition. A maliciously crafted file can fill the heap in a single read operation without properly releasing it.

- [https://github.com/Summitvc/cve-2026-3650](https://github.com/Summitvc/cve-2026-3650) :  ![starts](https://img.shields.io/github/stars/Summitvc/cve-2026-3650.svg) ![forks](https://img.shields.io/github/forks/Summitvc/cve-2026-3650.svg)


## CVE-2026-3143
 The Total Upkeep – WordPress Backup Plugin plus Restore & Migrate by BoldGrid plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'wp_ajax_cli_cancel' function in all versions up to, and including, 1.17.1. This makes it possible for unauthenticated attackers to cancel a pending rollback, potentially preventing a WordPress installation from automatically reverting a failed update.

- [https://github.com/ClimbMunchkin/fix-cve-2026-3143](https://github.com/ClimbMunchkin/fix-cve-2026-3143) :  ![starts](https://img.shields.io/github/stars/ClimbMunchkin/fix-cve-2026-3143.svg) ![forks](https://img.shields.io/github/forks/ClimbMunchkin/fix-cve-2026-3143.svg)


## CVE-2026-1096
 The Best-wp-google-map plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'latitude' and 'longitudinal' parameters of the 'google_map_view' shortcode in all versions up to, and including, 2.1 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/TheMursalin/CVE-2026-109618](https://github.com/TheMursalin/CVE-2026-109618) :  ![starts](https://img.shields.io/github/stars/TheMursalin/CVE-2026-109618.svg) ![forks](https://img.shields.io/github/forks/TheMursalin/CVE-2026-109618.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/yz9yt/React2Shell-CTF](https://github.com/yz9yt/React2Shell-CTF) :  ![starts](https://img.shields.io/github/stars/yz9yt/React2Shell-CTF.svg) ![forks](https://img.shields.io/github/forks/yz9yt/React2Shell-CTF.svg)


## CVE-2025-5518
This issue affects BILGER: before 2.4.6.

- [https://github.com/SpeatX/React2Shell-CVE-2025-55182](https://github.com/SpeatX/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/SpeatX/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/SpeatX/React2Shell-CVE-2025-55182.svg)
- [https://github.com/oways/React2shell-CVE-2025-55182-checker](https://github.com/oways/React2shell-CVE-2025-55182-checker) :  ![starts](https://img.shields.io/github/stars/oways/React2shell-CVE-2025-55182-checker.svg) ![forks](https://img.shields.io/github/forks/oways/React2shell-CVE-2025-55182-checker.svg)


## CVE-2024-6387
 A security regression (CVE-2006-5051) was discovered in OpenSSH's server (sshd). There is a race condition which can lead sshd to handle some signals in an unsafe manner. An unauthenticated, remote attacker may be able to trigger it by failing to authenticate within a set time period.

- [https://github.com/vkaushik-chef/regreSSHion](https://github.com/vkaushik-chef/regreSSHion) :  ![starts](https://img.shields.io/github/stars/vkaushik-chef/regreSSHion.svg) ![forks](https://img.shields.io/github/forks/vkaushik-chef/regreSSHion.svg)


## CVE-2023-22515
Atlassian Cloud sites are not affected by this vulnerability. If your Confluence site is accessed via an atlassian.net domain, it is hosted by Atlassian and is not vulnerable to this issue.

- [https://github.com/oshaie2/CVE-2023-22515-Incident-Response](https://github.com/oshaie2/CVE-2023-22515-Incident-Response) :  ![starts](https://img.shields.io/github/stars/oshaie2/CVE-2023-22515-Incident-Response.svg) ![forks](https://img.shields.io/github/forks/oshaie2/CVE-2023-22515-Incident-Response.svg)


## CVE-2021-4177
 livehelperchat is vulnerable to Generation of Error Message Containing Sensitive Information

- [https://github.com/gunzf0x/CVE-2021-41773](https://github.com/gunzf0x/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/gunzf0x/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/gunzf0x/CVE-2021-41773.svg)
- [https://github.com/sotiak/CVE-2021-41773](https://github.com/sotiak/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/sotiak/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/sotiak/CVE-2021-41773.svg)
- [https://github.com/R3leant/CVE-2021-41773](https://github.com/R3leant/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/R3leant/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/R3leant/CVE-2021-41773.svg)


## CVE-2017-5941
 An issue was discovered in the node-serialize package 0.0.4 for Node.js. Untrusted data passed into the unserialize() function can be exploited to achieve arbitrary code execution by passing a JavaScript Object with an Immediately Invoked Function Expression (IIFE).

- [https://github.com/DLL00P/CVE-2017-5941](https://github.com/DLL00P/CVE-2017-5941) :  ![starts](https://img.shields.io/github/stars/DLL00P/CVE-2017-5941.svg) ![forks](https://img.shields.io/github/forks/DLL00P/CVE-2017-5941.svg)


## CVE-2017-0199
 Microsoft Office 2007 SP3, Microsoft Office 2010 SP2, Microsoft Office 2013 SP1, Microsoft Office 2016, Microsoft Windows Vista SP2, Windows Server 2008 SP2, Windows 7 SP1, Windows 8.1 allow remote attackers to execute arbitrary code via a crafted document, aka "Microsoft Office/WordPad Remote Code Execution Vulnerability w/Windows API."

- [https://github.com/avidosa/MalwareStaticLab](https://github.com/avidosa/MalwareStaticLab) :  ![starts](https://img.shields.io/github/stars/avidosa/MalwareStaticLab.svg) ![forks](https://img.shields.io/github/forks/avidosa/MalwareStaticLab.svg)


## CVE-2011-2523
 vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

- [https://github.com/Davidrs000/Tproot-Dockerlabs](https://github.com/Davidrs000/Tproot-Dockerlabs) :  ![starts](https://img.shields.io/github/stars/Davidrs000/Tproot-Dockerlabs.svg) ![forks](https://img.shields.io/github/forks/Davidrs000/Tproot-Dockerlabs.svg)


## CVE-2004-1561
 Buffer overflow in Icecast 2.0.1 and earlier allows remote attackers to execute arbitrary code via an HTTP request with a large number of headers.

- [https://github.com/anway8090/Tryhackme-ice-lab-](https://github.com/anway8090/Tryhackme-ice-lab-) :  ![starts](https://img.shields.io/github/stars/anway8090/Tryhackme-ice-lab-.svg) ![forks](https://img.shields.io/github/forks/anway8090/Tryhackme-ice-lab-.svg)

