# Update 2025-12-31
## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-68645](https://github.com/Ashwesker/Ashwesker-CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-68645.svg)


## CVE-2025-68615
 net-snmp is a SNMP application library, tools and daemon. Prior to versions 5.9.5 and 5.10.pre2, a specially crafted packet to an net-snmp snmptrapd daemon can cause a buffer overflow and the daemon to crash. This issue has been patched in versions 5.9.5 and 5.10.pre2.

- [https://github.com/yt2w/CVE-2025-68615](https://github.com/yt2w/CVE-2025-68615) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-68615.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-68615.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-68613](https://github.com/Ashwesker/Ashwesker-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-68613.svg)
- [https://github.com/cv-sai-kamesh/n8n-CVE-2025-68613](https://github.com/cv-sai-kamesh/n8n-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/cv-sai-kamesh/n8n-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/cv-sai-kamesh/n8n-CVE-2025-68613.svg)


## CVE-2025-67779
 It was found that the fix addressing CVE-2025-55184 in React Server Components was incomplete and does not prevent a denial of service attack in a specific case. React Server Components versions 19.0.2, 19.1.3 and 19.2.2 are affected, allowing unsafe deserialization of payloads from HTTP requests to Server Function endpoints. This can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/Black-and-reds/reactguard](https://github.com/Black-and-reds/reactguard) :  ![starts](https://img.shields.io/github/stars/Black-and-reds/reactguard.svg) ![forks](https://img.shields.io/github/forks/Black-and-reds/reactguard.svg)


## CVE-2025-66644
 Array Networks ArrayOS AG before 9.4.5.9 allows command injection, as exploited in the wild in August through December 2025.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-66644](https://github.com/Ashwesker/Ashwesker-CVE-2025-66644) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-66644.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-66644.svg)


## CVE-2025-66516
Second, the original report failed to mention that in the 1.x Tika releases, the PDFParser was in the "org.apache.tika:tika-parsers" module.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-66516](https://github.com/Ashwesker/Ashwesker-CVE-2025-66516) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-66516.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-66516.svg)


## CVE-2025-66489
 Cal.com is open-source scheduling software. Prior to 5.9.8, A flaw in the login credentials provider allows an attacker to bypass password verification when a TOTP code is provided, potentially gaining unauthorized access to user accounts. This issue exists due to problematic conditional logic in the authentication flow. This vulnerability is fixed in 5.9.8.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-66489](https://github.com/Ashwesker/Ashwesker-CVE-2025-66489) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-66489.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-66489.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-overrides.svg)


## CVE-2025-66429
 An issue was discovered in cPanel 110 through 132. A directory traversal vulnerability within the Team Manager API allows for overwrite of an arbitrary file. This can allow for privilege escalation to the root user.

- [https://github.com/baseng1337/CVE-2025-66429](https://github.com/baseng1337/CVE-2025-66429) :  ![starts](https://img.shields.io/github/stars/baseng1337/CVE-2025-66429.svg) ![forks](https://img.shields.io/github/forks/baseng1337/CVE-2025-66429.svg)


## CVE-2025-65964
 n8n is an open source workflow automation platform. Versions 0.123.1 through 1.119.1 do not have adequate protections to prevent RCE through the project's pre-commit hooks. The Add Config operation allows workflows to set arbitrary Git configuration values, including core.hooksPath, which can point to a malicious Git hook that executes arbitrary commands on the n8n host during subsequent Git operations. Exploitation requires the ability to create or modify an n8n workflow using the Git node. This issue is fixed in version 1.119.2. Workarounds include excluding the Git Node (Docs) and avoiding cloning or interacting with untrusted repositories using the Git Node.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-65964](https://github.com/Ashwesker/Ashwesker-CVE-2025-65964) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-65964.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-65964.svg)


## CVE-2025-65442
 DOM-based Cross-Site Scripting (XSS) vulnerability in 201206030 novel V3.5.0 allows remote attackers to execute arbitrary JavaScript code or disclose sensitive information (e.g., user session cookies) via a crafted "wvstest" parameter in the URL or malicious script injection into window.localStorage. The vulnerability arises from insufficient validation and encoding of user-controllable data in the book comment module: unfiltered user input is stored in the backend database (book_comment table, commentContent field) and returned via API, then rendered directly into the page DOM via Vue 3's v-html directive without sanitization. Even if modern browsers' built-in XSS filters block pop-up alerts, attackers can use concealed payloads to bypass interception and achieve actual harm.

- [https://github.com/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-](https://github.com/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-) :  ![starts](https://img.shields.io/github/stars/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-.svg) ![forks](https://img.shields.io/github/forks/zero-day348/CVE-2025-65442-DOM-based-Cross-Site-Scripting-XSS-Vulnerability-in-novel-V3.5.0-CWE-79-.svg)


## CVE-2025-64513
 Milvus is an open-source vector database built for generative AI applications. An unauthenticated attacker can exploit a vulnerability in versions prior to 2.4.24, 2.5.21, and 2.6.5 to bypass all authentication mechanisms in the Milvus Proxy component, gaining full administrative access to the Milvus cluster. This grants the attacker the ability to read, modify, or delete data, and to perform privileged administrative operations such as database or collection management. This issue has been fixed in Milvus 2.4.24, 2.5.21, and 2.6.5. If immediate upgrade is not possible, a temporary mitigation can be applied by removing the sourceID header from all incoming requests at the gateway, API gateway, or load balancer level before they reach the Milvus Proxy. This prevents attackers from exploiting the authentication bypass behavior.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64513](https://github.com/Ashwesker/Ashwesker-CVE-2025-64513) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64513.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64513.svg)


## CVE-2025-64500
 Symfony is a PHP framework for web and console applications and a set of reusable PHP components. Symfony's HttpFoundation component defines an object-oriented layer for the HTTP specification. Starting in version 2.0.0 and prior to version 5.4.50, 6.4.29, and 7.3.7, the `Request` class improperly interprets some `PATH_INFO` in a way that leads to representing some URLs with a path that doesn't start with a `/`. This can allow bypassing some access control rules that are built with this `/`-prefix assumption. Starting in versions 5.4.50, 6.4.29, and 7.3.7, the `Request` class now ensures that URL paths always start with a `/`.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64500](https://github.com/Ashwesker/Ashwesker-CVE-2025-64500) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64500.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64500.svg)


## CVE-2025-64495
 Open WebUI is a self-hosted artificial intelligence platform designed to operate entirely offline. In versions 0.6.34 and below, the functionality that inserts custom prompts into the chat window is vulnerable to DOM XSS when 'Insert Prompt as Rich Text' is enabled, since the prompt body is assigned to the DOM sink .innerHtml without sanitisation. Any user with permissions to create prompts can abuse this to plant a payload that could be triggered by other users if they run the corresponding / command to insert the prompt. This issue is fixed in version 0.6.35.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64495](https://github.com/Ashwesker/Ashwesker-CVE-2025-64495) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64495.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64495.svg)


## CVE-2025-64484
 OAuth2-Proxy is an open-source tool that can act as either a standalone reverse proxy or a middleware component integrated into existing reverse proxy or load balancer setups. In versions prior to 7.13.0, all deployments of OAuth2 Proxy in front of applications that normalize underscores to dashes in HTTP headers (e.g., WSGI-based frameworks such as Django, Flask, FastAPI, and PHP applications). Authenticated users can inject underscore variants of X-Forwarded-* headers that bypass the proxy’s filtering logic, potentially escalating privileges in the upstream app. OAuth2 Proxy authentication/authorization itself is not compromised. The problem has been patched with v7.13.0. By default all specified headers will now be normalized, meaning that both capitalization and the use of underscores (_) versus dashes (-) will be ignored when matching headers to be stripped. For example, both `X-Forwarded-For` and `X_Forwarded-for` will now be treated as equivalent and stripped away. For those who have a rational that requires keeping a similar looking header and not stripping it, the maintainers introduced a new configuration field for Headers managed through the AlphaConfig called `InsecureSkipHeaderNormalization`. As a workaround, ensure filtering and processing logic in upstream services don't treat underscores and hyphens in Headers the same way.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64484](https://github.com/Ashwesker/Ashwesker-CVE-2025-64484) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64484.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64484.svg)


## CVE-2025-64459
Django would like to thank cyberstan for reporting this issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64459](https://github.com/Ashwesker/Ashwesker-CVE-2025-64459) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64459.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64459.svg)


## CVE-2025-64446
 A relative path traversal vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.4, FortiWeb 7.4.0 through 7.4.9, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an attacker to execute administrative commands on the system via crafted HTTP or HTTPS requests.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64446](https://github.com/Ashwesker/Ashwesker-CVE-2025-64446) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64446.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64446.svg)


## CVE-2025-64113
 Emby Server is a user-installable home media server. Versions below 4.9.1.81 allow an attacker to gain full administrative access to an Emby Server (for Emby Server administration, not at the OS level). Other than network access, no specific preconditions need to be fulfilled for a server to be vulnerable. This issue is fixed in version 4.9.1.81.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-64113](https://github.com/Ashwesker/Ashwesker-CVE-2025-64113) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-64113.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-64113.svg)


## CVE-2025-63334
 PocketVJ CP PocketVJ-CP-v3 pvj version 3.9.1 contains an unauthenticated remote code execution vulnerability in the submit_opacity.php component. The application fails to sanitize user input in the opacityValue POST parameter before passing it to a shell command, allowing remote attackers to execute arbitrary commands with root privileges on the underlying system.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-63334](https://github.com/Ashwesker/Ashwesker-CVE-2025-63334) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-63334.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-63334.svg)


## CVE-2025-62593
 Ray is an AI compute engine. Prior to version 2.52.0, developers working with Ray as a development tool can be exploited via a critical RCE vulnerability exploitable via Firefox and Safari. This vulnerability is due to an insufficient guard against browser-based attacks, as the current defense uses the User-Agent header starting with the string "Mozilla" as a defense mechanism. This defense is insufficient as the fetch specification allows the User-Agent header to be modified. Combined with a DNS rebinding attack against the browser, and this vulnerability is exploitable against a developer running Ray who inadvertently visits a malicious website, or is served a malicious advertisement (malvertising). This issue has been patched in version 2.52.0.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-62593](https://github.com/Ashwesker/Ashwesker-CVE-2025-62593) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-62593.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-62593.svg)


## CVE-2025-62481
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.  Successful attacks of this vulnerability can result in takeover of Oracle Marketing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-62481](https://github.com/Ashwesker/Ashwesker-CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-62481.svg)


## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-61884](https://github.com/Ashwesker/Ashwesker-CVE-2025-61884) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-61884.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-61884.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-61882](https://github.com/Ashwesker/Ashwesker-CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-61882.svg)


## CVE-2025-61757
 Vulnerability in the Identity Manager product of Oracle Fusion Middleware (component: REST WebServices).  Supported versions that are affected are 12.2.1.4.0 and  14.1.2.1.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Identity Manager.  Successful attacks of this vulnerability can result in takeover of Identity Manager. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-61757](https://github.com/Ashwesker/Ashwesker-CVE-2025-61757) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-61757.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-61757.svg)


## CVE-2025-61481
 An issue in MikroTik RouterOS v.7.14.2 and SwOS v.2.18 exposes the WebFig management interface over cleartext HTTP by default, allowing an on-path attacker to execute injected JavaScript in the administrator’s browser and intercept credentials.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-61481](https://github.com/Ashwesker/Ashwesker-CVE-2025-61481) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-61481.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-61481.svg)


## CVE-2025-60458
 UxPlay 1.72 contains a double free vulnerability in its RTSP request handling. A specially crafted RTSP TEARDOWN request can trigger multiple calls to free() on the same memory address, potentially causing a Denial of Service.

- [https://github.com/0pepsi/CVE-2025-60458](https://github.com/0pepsi/CVE-2025-60458) :  ![starts](https://img.shields.io/github/stars/0pepsi/CVE-2025-60458.svg) ![forks](https://img.shields.io/github/forks/0pepsi/CVE-2025-60458.svg)


## CVE-2025-59718
 A improper verification of cryptographic signature vulnerability in Fortinet FortiOS 7.6.0 through 7.6.3, FortiOS 7.4.0 through 7.4.8, FortiOS 7.2.0 through 7.2.11, FortiOS 7.0.0 through 7.0.17, FortiProxy 7.6.0 through 7.6.3, FortiProxy 7.4.0 through 7.4.10, FortiProxy 7.2.0 through 7.2.14, FortiProxy 7.0.0 through 7.0.21, FortiSwitchManager 7.2.0 through 7.2.6, FortiSwitchManager 7.0.0 through 7.0.5 allows an unauthenticated attacker to bypass the FortiCloud SSO login authentication via a crafted SAML response message.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-59718](https://github.com/Ashwesker/Ashwesker-CVE-2025-59718) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-59718.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-59718.svg)


## CVE-2025-59528
 Flowise is a drag & drop user interface to build a customized large language model flow. In version 3.0.5, Flowise is vulnerable to remote code execution. The CustomMCP node allows users to input configuration settings for connecting to an external MCP server. This node parses the user-provided mcpServerConfig string to build the MCP server configuration. However, during this process, it executes JavaScript code without any security validation. Specifically, inside the convertToValidJSONString function, user input is directly passed to the Function() constructor, which evaluates and executes the input as JavaScript code. Since this runs with full Node.js runtime privileges, it can access dangerous modules such as child_process and fs. This issue has been patched in version 3.0.6.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-59528](https://github.com/Ashwesker/Ashwesker-CVE-2025-59528) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-59528.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-59528.svg)


## CVE-2025-59367
 An authentication bypass vulnerability has been identified in certain DSL series routers, may allow remote attackers to gain unauthorized access into the affected system. Refer to the 'Security Update for DSL Series Router' section on the ASUS Security Advisory for more information.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-59367](https://github.com/Ashwesker/Ashwesker-CVE-2025-59367) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-59367.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-59367.svg)


## CVE-2025-59118
Users are recommended to upgrade to version 24.09.03, which fixes the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-59118](https://github.com/Ashwesker/Ashwesker-CVE-2025-59118) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-59118.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-59118.svg)


## CVE-2025-58360
 GeoServer is an open source server that allows users to share and edit geospatial data. From version 2.26.0 to before 2.26.2 and before 2.25.6, an XML External Entity (XXE) vulnerability was identified. The application accepts XML input through a specific endpoint /geoserver/wms operation GetMap. However, this input is not sufficiently sanitized or restricted, allowing an attacker to define external entities within the XML request. This issue has been patched in GeoServer 2.25.6, GeoServer 2.26.3, and GeoServer 2.27.0.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-58360](https://github.com/Ashwesker/Ashwesker-CVE-2025-58360) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-58360.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-58360.svg)


## CVE-2025-58034
 An Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability [CWE-78] vulnerability in Fortinet FortiWeb 8.0.0 through 8.0.1, FortiWeb 7.6.0 through 7.6.5, FortiWeb 7.4.0 through 7.4.10, FortiWeb 7.2.0 through 7.2.11, FortiWeb 7.0.0 through 7.0.11 may allow an authenticated attacker to execute unauthorized code on the underlying system via crafted HTTP requests or CLI commands.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-58034](https://github.com/Ashwesker/Ashwesker-CVE-2025-58034) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-58034.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-58034.svg)


## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-57819](https://github.com/Ashwesker/Ashwesker-CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-57819.svg)


## CVE-2025-57773
 DataEase is an open source business intelligence and data visualization tool. Prior to version 2.10.12, because DB2 parameters are not filtered, a JNDI injection attack can be directly launched. JNDI triggers an AspectJWeaver deserialization attack, writing to various files. This vulnerability requires commons-collections 4.x and aspectjweaver-1.9.22.jar. The vulnerability has been fixed in version 2.10.12.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-57773](https://github.com/Ashwesker/Ashwesker-CVE-2025-57773) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-57773.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-57773.svg)


## CVE-2025-57462
 Reflected Cross site scripting (xss) in machsol machpanel 8.0.32 allows attackers to execute arbitrary web scripts or HTML via a crafted PDF file.

- [https://github.com/aljoharasubaie/CVE-2025-57462](https://github.com/aljoharasubaie/CVE-2025-57462) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-57462.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-57462.svg)


## CVE-2025-57460
 File upload vulnerability in machsol machpanel 8.0.32 allows attacker to gain a webshell.

- [https://github.com/aljoharasubaie/CVE-2025-57460](https://github.com/aljoharasubaie/CVE-2025-57460) :  ![starts](https://img.shields.io/github/stars/aljoharasubaie/CVE-2025-57460.svg) ![forks](https://img.shields.io/github/forks/aljoharasubaie/CVE-2025-57460.svg)


## CVE-2025-57105
 The DI-7400G+ router has a command injection vulnerability, which allows attackers to execute arbitrary commands on the device. The sub_478D28 function in in mng_platform.asp, and sub_4A12DC function in wayos_ac_server.asp of the jhttpd program, with the parameter ac_mng_srv_host.

- [https://github.com/yt2w/CVE-2025-57105](https://github.com/yt2w/CVE-2025-57105) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-57105.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-57105.svg)


## CVE-2025-55752
Users are recommended to upgrade to version 11.0.11 or later, 10.1.45 or later or 9.0.109 or later, which fix the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-55752](https://github.com/Ashwesker/Ashwesker-CVE-2025-55752) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-55752.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-55752.svg)


## CVE-2025-55184
 A pre-authentication denial of service vulnerability exists in React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints, which can cause an infinite loop that hangs the server process and may prevent future HTTP requests from being served.

- [https://github.com/Black-and-reds/reactguard](https://github.com/Black-and-reds/reactguard) :  ![starts](https://img.shields.io/github/stars/Black-and-reds/reactguard.svg) ![forks](https://img.shields.io/github/forks/Black-and-reds/reactguard.svg)


## CVE-2025-55183
 An information leak vulnerability exists in specific configurations of React Server Components versions 19.0.0, 19.0.1 19.1.0, 19.1.1, 19.1.2, 19.2.0 and 19.2.1, including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. A specifically crafted HTTP request sent to a vulnerable Server Function may unsafely return the source code of any Server Function. Exploitation requires the existence of a Server Function which explicitly or implicitly exposes a stringified argument.

- [https://github.com/Black-and-reds/reactguard](https://github.com/Black-and-reds/reactguard) :  ![starts](https://img.shields.io/github/stars/Black-and-reds/reactguard.svg) ![forks](https://img.shields.io/github/forks/Black-and-reds/reactguard.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-55182](https://github.com/Ashwesker/Ashwesker-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-55182.svg)


## CVE-2025-54574
 Squid is a caching proxy for the Web. In versions 6.3 and below, Squid is vulnerable to a heap buffer overflow and possible remote code execution attack when processing URN due to incorrect buffer management. This has been fixed in version 6.4. To work around this issue, disable URN access permissions.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-54574](https://github.com/Ashwesker/Ashwesker-CVE-2025-54574) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-54574.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-54574.svg)


## CVE-2025-54381
 BentoML is a Python library for building online serving systems optimized for AI apps and model inference. In versions 1.4.0 until 1.4.19, the file upload processing system contains an SSRF vulnerability that allows unauthenticated remote attackers to force the server to make arbitrary HTTP requests. The vulnerability stems from the multipart form data and JSON request handlers, which automatically download files from user-provided URLs without validating whether those URLs point to internal network addresses, cloud metadata endpoints, or other restricted resources. The documentation explicitly promotes this URL-based file upload feature, making it an intended design that exposes all deployed services to SSRF attacks by default. Version 1.4.19 contains a patch for the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-54381](https://github.com/Ashwesker/Ashwesker-CVE-2025-54381) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-54381.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-54381.svg)


## CVE-2025-54253
 Adobe Experience Manager versions 6.5.23 and earlier are affected by a Misconfiguration vulnerability that could result in arbitrary code execution. An attacker could leverage this vulnerability to bypass security mechanisms and execute code. Exploitation of this issue does not require user interaction and scope is changed.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-54253](https://github.com/Ashwesker/Ashwesker-CVE-2025-54253) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-54253.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-54253.svg)


## CVE-2025-54100
 Improper neutralization of special elements used in a command ('command injection') in Windows PowerShell allows an unauthorized attacker to execute code locally.

- [https://github.com/xiaoLvChen/CVE-2025-54100](https://github.com/xiaoLvChen/CVE-2025-54100) :  ![starts](https://img.shields.io/github/stars/xiaoLvChen/CVE-2025-54100.svg) ![forks](https://img.shields.io/github/forks/xiaoLvChen/CVE-2025-54100.svg)


## CVE-2025-53833
 LaRecipe is an application that allows users to create documentation with Markdown inside a Laravel app. Versions prior to 2.8.1 are vulnerable to Server-Side Template Injection (SSTI), which could potentially lead to Remote Code Execution (RCE) in vulnerable configurations. Attackers could execute arbitrary commands on the server, access sensitive environment variables, and/or escalate access depending on server configuration. Users are strongly advised to upgrade to version v2.8.1 or later to receive a patch.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-53833](https://github.com/Ashwesker/Ashwesker-CVE-2025-53833) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-53833.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-53833.svg)


## CVE-2025-53773
 Improper neutralization of special elements used in a command ('command injection') in GitHub Copilot and Visual Studio allows an unauthorized attacker to execute code locally.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-53773](https://github.com/Ashwesker/Ashwesker-CVE-2025-53773) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-53773.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-53773.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-53770](https://github.com/Ashwesker/Ashwesker-CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-53770.svg)


## CVE-2025-53690
 Deserialization of Untrusted Data vulnerability in Sitecore Experience Manager (XM), Sitecore Experience Platform (XP) allows Code Injection.This issue affects Experience Manager (XM): through 9.0; Experience Platform (XP): through 9.0.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-53690](https://github.com/Ashwesker/Ashwesker-CVE-2025-53690) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-53690.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-53690.svg)


## CVE-2025-53072
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.  Successful attacks of this vulnerability can result in takeover of Oracle Marketing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-53072](https://github.com/Ashwesker/Ashwesker-CVE-2025-53072) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-53072.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-53072.svg)


## CVE-2025-52692
 Successful exploitation of the vulnerability could allow an attacker with local network access to send a specially crafted URL to access certain administration functions without login credentials.

- [https://github.com/yt2w/CVE-2025-52692](https://github.com/yt2w/CVE-2025-52692) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-52692.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-52692.svg)


## CVE-2025-52691
 Successful exploitation of the vulnerability could allow an unauthenticated attacker to upload arbitrary files to any location on the mail server, potentially enabling remote code execution.

- [https://github.com/yt2w/CVE-2025-52691](https://github.com/yt2w/CVE-2025-52691) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-52691.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-52691.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-49844](https://github.com/Ashwesker/Ashwesker-CVE-2025-49844) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-49844.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-49844.svg)


## CVE-2025-49493
 Akamai CloudTest before 60 2025.06.02 (12988) allows file inclusion via XML External Entity (XXE) injection.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-49493](https://github.com/Ashwesker/Ashwesker-CVE-2025-49493) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-49493.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-49493.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-49113](https://github.com/Ashwesker/Ashwesker-CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-49113.svg)


## CVE-2025-48633
 In hasAccountsOnAnyUser of DevicePolicyManagerService.java, there is a possible way to add a Device Owner after provisioning due to a logic error in the code. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-48633](https://github.com/Ashwesker/Ashwesker-CVE-2025-48633) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-48633.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-48633.svg)


## CVE-2025-48593
 In bta_hf_client_cb_init of bta_hf_client_main.cc, there is a possible remote code execution due to a use after free. This could lead to remote code execution with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-48593](https://github.com/Ashwesker/Ashwesker-CVE-2025-48593) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-48593.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-48593.svg)


## CVE-2025-47812
 In Wing FTP Server before 7.4.4. the user and admin web interfaces mishandle '\0' bytes, ultimately allowing injection of arbitrary Lua code into user session files. This can be used to execute arbitrary system commands with the privileges of the FTP service (root or SYSTEM by default). This is thus a remote code execution vulnerability that guarantees a total server compromise. This is also exploitable via anonymous FTP accounts.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-47812](https://github.com/Ashwesker/Ashwesker-CVE-2025-47812) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-47812.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-47812.svg)


## CVE-2025-47227
 In the Production Environment extension in Netmake ScriptCase through 9.12.006 (23), the Administrator password reset mechanism is mishandled. Making both a GET and a POST request to login.php.is sufficient. An unauthenticated attacker can then bypass authentication via administrator account takeover.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-47227](https://github.com/Ashwesker/Ashwesker-CVE-2025-47227) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-47227.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-47227.svg)


## CVE-2025-41115
- `user_sync_enabled` config option in the `[auth.scim]` block set to true

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-41115](https://github.com/Ashwesker/Ashwesker-CVE-2025-41115) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-41115.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-41115.svg)


## CVE-2025-40547
This issue requires administrative privileges to abuse. On Windows deployments, the risk is scored as a medium because services frequently run under less-privileged service accounts by default.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-40547](https://github.com/Ashwesker/Ashwesker-CVE-2025-40547) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-40547.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-40547.svg)


## CVE-2025-36250
 IBM AIX 7.2, and 7.3 and IBM VIOS 3.1, and 4.1 NIM server (formerly known as NIM master) service (nimesis) could allow a remote attacker to execute arbitrary commands due to improper process controls.  This addresses additional attack vectors for a vulnerability that was previously addressed in CVE-2024-56346.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-36250](https://github.com/Ashwesker/Ashwesker-CVE-2025-36250) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-36250.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-36250.svg)


## CVE-2025-34299
 Monsta FTP versions 2.11 and earlier contain a vulnerability that allows unauthenticated arbitrary file uploads. This flaw enables attackers to execute arbitrary code by uploading a specially crafted file from a malicious (S)FTP server.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-34299](https://github.com/Ashwesker/Ashwesker-CVE-2025-34299) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-34299.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-34299.svg)


## CVE-2025-34085
 This CVE ID has been rejected or withdrawn by its CVE Numbering Authority as it is a duplicate of CVE-2020-36847.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-34085](https://github.com/Ashwesker/Ashwesker-CVE-2025-34085) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-34085.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-34085.svg)


## CVE-2025-33073
 Improper access control in Windows SMB allows an authorized attacker to elevate privileges over a network.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-33073](https://github.com/Ashwesker/Ashwesker-CVE-2025-33073) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-33073.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-33073.svg)


## CVE-2025-32756
 A stack-based buffer overflow vulnerability [CWE-121] in Fortinet FortiVoice versions 7.2.0, 7.0.0 through 7.0.6, 6.4.0 through 6.4.10, FortiRecorder versions 7.2.0 through 7.2.3, 7.0.0 through 7.0.5, 6.4.0 through 6.4.5, FortiMail versions 7.6.0 through 7.6.2, 7.4.0 through 7.4.4, 7.2.0 through 7.2.7, 7.0.0 through 7.0.8, FortiNDR versions 7.6.0, 7.4.0 through 7.4.7, 7.2.0 through 7.2.4, 7.0.0 through 7.0.6, FortiCamera versions 2.1.0 through 2.1.3, 2.0 all versions, 1.1 all versions, allows a remote unauthenticated attacker to execute arbitrary code or commands via sending HTTP requests with specially crafted hash cookie.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-32756](https://github.com/Ashwesker/Ashwesker-CVE-2025-32756) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-32756.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-32756.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-32463](https://github.com/Ashwesker/Ashwesker-CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-32463.svg)
- [https://github.com/aexdyhaxor/CVE-2025-32463](https://github.com/aexdyhaxor/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/aexdyhaxor/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/aexdyhaxor/CVE-2025-32463.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/AntonieSoga/Erlang-OTP-PoC_CVE-2025-32433](https://github.com/AntonieSoga/Erlang-OTP-PoC_CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/AntonieSoga/Erlang-OTP-PoC_CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/AntonieSoga/Erlang-OTP-PoC_CVE-2025-32433.svg)
- [https://github.com/Ashwesker/Ashwesker-CVE-2025-32433](https://github.com/Ashwesker/Ashwesker-CVE-2025-32433) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-32433.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-32433.svg)


## CVE-2025-32432
 Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to remote code execution. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-32432](https://github.com/Ashwesker/Ashwesker-CVE-2025-32432) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-32432.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-32432.svg)


## CVE-2025-32023
 Redis is an open source, in-memory database that persists on disk. From 2.8 to before 8.0.3, 7.4.5, 7.2.10, and 6.2.19, an authenticated user may use a specially crafted string to trigger a stack/heap out of bounds write on hyperloglog operations, potentially leading to remote code execution. The bug likely affects all Redis versions with hyperloglog operations implemented. This vulnerability is fixed in 8.0.3, 7.4.5, 7.2.10, and 6.2.19. An additional workaround to mitigate the problem without patching the redis-server executable is to prevent users from executing hyperloglog operations. This can be done using ACL to restrict HLL commands.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-32023](https://github.com/Ashwesker/Ashwesker-CVE-2025-32023) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-32023.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-32023.svg)


## CVE-2025-31161
 CrushFTP 10 before 10.8.4 and 11 before 11.3.1 allows authentication bypass and takeover of the crushadmin account (unless a DMZ proxy instance is used), as exploited in the wild in March and April 2025, aka "Unauthenticated HTTP(S) port access." A race condition exists in the AWS4-HMAC (compatible with S3) authorization method of the HTTP component of the FTP server. The server first verifies the existence of the user by performing a call to login_user_pass() with no password requirement. This will authenticate the session through the HMAC verification process and up until the server checks for user verification once more. The vulnerability can be further stabilized, eliminating the need for successfully triggering a race condition, by sending a mangled AWS4-HMAC header. By providing only the username and a following slash (/), the server will successfully find a username, which triggers the successful anypass authentication process, but the server will fail to find the expected SignedHeaders entry, resulting in an index-out-of-bounds error that stops the code from reaching the session cleanup. Together, these issues make it trivial to authenticate as any known or guessable user (e.g., crushadmin), and can lead to a full compromise of the system by obtaining an administrative account.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-31161](https://github.com/Ashwesker/Ashwesker-CVE-2025-31161) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-31161.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-31161.svg)


## CVE-2025-31131
 YesWiki is a wiki system written in PHP. The squelette parameter is vulnerable to path traversal attacks, enabling read access to arbitrary files on the server. This vulnerability is fixed in 4.5.2.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-31131](https://github.com/Ashwesker/Ashwesker-CVE-2025-31131) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-31131.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-31131.svg)


## CVE-2025-30397
 Access of resource using incompatible type ('type confusion') in Microsoft Scripting Engine allows an unauthorized attacker to execute code over a network.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-30397](https://github.com/Ashwesker/Ashwesker-CVE-2025-30397) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-30397.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-30397.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-30208](https://github.com/Ashwesker/Ashwesker-CVE-2025-30208) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-30208.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-30208.svg)


## CVE-2025-30065
Users are recommended to upgrade to version 1.15.1, which fixes the issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-30065](https://github.com/Ashwesker/Ashwesker-CVE-2025-30065) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-30065.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-30065.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-29927](https://github.com/Ashwesker/Ashwesker-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-29927.svg)
- [https://github.com/enochgitgamefied/NextJS-CVE-2025-29927](https://github.com/enochgitgamefied/NextJS-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/enochgitgamefied/NextJS-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/enochgitgamefied/NextJS-CVE-2025-29927.svg)


## CVE-2025-29306
 An issue in FoxCMS v.1.2.5 allows a remote attacker to execute arbitrary code via the case display page in the index.html component.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-29306](https://github.com/Ashwesker/Ashwesker-CVE-2025-29306) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-29306.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-29306.svg)


## CVE-2025-27210
This vulnerability affects Windows users of `path.join` API.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-27210](https://github.com/Ashwesker/Ashwesker-CVE-2025-27210) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-27210.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-27210.svg)


## CVE-2025-25257
 An improper neutralization of special elements used in an SQL command ('SQL Injection') vulnerability [CWE-89] in Fortinet FortiWeb version 7.6.0 through 7.6.3, 7.4.0 through 7.4.7, 7.2.0 through 7.2.10 and below 7.0.10 allows an unauthenticated attacker to execute unauthorized SQL code or commands via crafted HTTP or HTTPs requests.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-25257](https://github.com/Ashwesker/Ashwesker-CVE-2025-25257) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-25257.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-25257.svg)


## CVE-2025-25014
 A Prototype pollution vulnerability in Kibana leads to arbitrary code execution via crafted HTTP requests to machine learning and reporting endpoints.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-25014](https://github.com/Ashwesker/Ashwesker-CVE-2025-25014) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-25014.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-25014.svg)


## CVE-2025-24893
 XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. Any guest can perform arbitrary remote code execution through a request to `SolrSearch`. This impacts the confidentiality, integrity and availability of the whole XWiki installation. To reproduce on an instance, without being logged in, go to `host/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28"Hello%20from"%20%2B%20"%20search%20text%3A"%20%2B%20%2823%20%2B%2019%29%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D%20`. If there is an output, and the title of the RSS feed contains `Hello from search text:42`, then the instance is vulnerable. This vulnerability has been patched in XWiki 15.10.11, 16.4.1 and 16.5.0RC1. Users are advised to upgrade. Users unable to upgrade may edit `Main.SolrSearchMacros` in `SolrSearchMacros.xml` on line 955 to match the `rawResponse` macro in `macros.vm#L2824` with a content type of `application/xml`, instead of simply outputting the content of the feed.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-24893](https://github.com/Ashwesker/Ashwesker-CVE-2025-24893) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-24893.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-24893.svg)


## CVE-2025-24252
 A use-after-free issue was addressed with improved memory management. This issue is fixed in macOS Sequoia 15.4, tvOS 18.4, macOS Ventura 13.7.5, iPadOS 17.7.6, macOS Sonoma 14.7.5, iOS 18.4 and iPadOS 18.4, visionOS 2.4. An attacker on the local network may be able to corrupt process memory.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-24252](https://github.com/Ashwesker/Ashwesker-CVE-2025-24252) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-24252.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-24252.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-24071](https://github.com/Ashwesker/Ashwesker-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-24071.svg)


## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-24016](https://github.com/Ashwesker/Ashwesker-CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-24016.svg)


## CVE-2025-22870
 Matching of hosts against proxy patterns can improperly treat an IPv6 zone ID as a hostname component. For example, when the NO_PROXY environment variable is set to "*.example.com", a request to "[::1%25.example.com]:80` will incorrectly match and not be proxied.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-22870](https://github.com/Ashwesker/Ashwesker-CVE-2025-22870) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-22870.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-22870.svg)


## CVE-2025-22777
 Deserialization of Untrusted Data vulnerability in GiveWP GiveWP allows Object Injection.This issue affects GiveWP: from n/a through 3.19.3.

- [https://github.com/SevDMG/CVE-2025-22777-GiveWP-Plugin-PHP-Object-Injection-Point-PoC-](https://github.com/SevDMG/CVE-2025-22777-GiveWP-Plugin-PHP-Object-Injection-Point-PoC-) :  ![starts](https://img.shields.io/github/stars/SevDMG/CVE-2025-22777-GiveWP-Plugin-PHP-Object-Injection-Point-PoC-.svg) ![forks](https://img.shields.io/github/forks/SevDMG/CVE-2025-22777-GiveWP-Plugin-PHP-Object-Injection-Point-PoC-.svg)


## CVE-2025-22457
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.6, Ivanti Policy Secure before version 22.7R1.4, and Ivanti ZTA Gateways before version 22.8R2.2 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-22457](https://github.com/Ashwesker/Ashwesker-CVE-2025-22457) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-22457.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-22457.svg)


## CVE-2025-21333
 Windows Hyper-V NT Kernel Integration VSP Elevation of Privilege Vulnerability

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-21333](https://github.com/Ashwesker/Ashwesker-CVE-2025-21333) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-21333.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-21333.svg)


## CVE-2025-21298
 Windows OLE Remote Code Execution Vulnerability

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-21298](https://github.com/Ashwesker/Ashwesker-CVE-2025-21298) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-21298.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-21298.svg)


## CVE-2025-21042
 Out-of-bounds write in libimagecodec.quram.so prior to SMR Apr-2025 Release 1 allows remote attackers to execute arbitrary code.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-21042](https://github.com/Ashwesker/Ashwesker-CVE-2025-21042) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-21042.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-21042.svg)


## CVE-2025-20393
 Cisco is aware of a potential vulnerability.&nbsp; Cisco is currently investigating and&nbsp;will update these details as appropriate&nbsp;as more information becomes available.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-20393](https://github.com/Ashwesker/Ashwesker-CVE-2025-20393) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-20393.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-20393.svg)


## CVE-2025-20354
This vulnerability is due to improper authentication mechanisms that are associated to specific Cisco Unified CCX features. An attacker could exploit this vulnerability by uploading a crafted file to an affected system through the Java RMI process. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system and elevate privileges to root.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-20354](https://github.com/Ashwesker/Ashwesker-CVE-2025-20354) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-20354.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-20354.svg)


## CVE-2025-20343
This vulnerability is due to a logic error when processing a RADIUS access request for a MAC address that is already a rejected endpoint. An attacker could exploit this vulnerability by sending a specific sequence of multiple crafted RADIUS access request messages to Cisco ISE. A successful exploit could allow the attacker to cause a denial of service (DoS) condition when Cisco ISE restarts.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-20343](https://github.com/Ashwesker/Ashwesker-CVE-2025-20343) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-20343.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-20343.svg)


## CVE-2025-20337
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-20337](https://github.com/Ashwesker/Ashwesker-CVE-2025-20337) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-20337.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-20337.svg)


## CVE-2025-20281
This vulnerability is due to insufficient validation of user-supplied input. An attacker could exploit this vulnerability by submitting a crafted API request. A successful exploit could allow the attacker to obtain root privileges on an affected device.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-20281](https://github.com/Ashwesker/Ashwesker-CVE-2025-20281) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-20281.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-20281.svg)


## CVE-2025-15177
 A vulnerability has been found in Tenda WH450 1.0.0.18. This vulnerability affects unknown code of the file /goform/SetIpBind of the component HTTP Request Handler. The manipulation of the argument page leads to stack-based buffer overflow. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/yt2w/CVE-2025-15177](https://github.com/yt2w/CVE-2025-15177) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-15177.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-15177.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/joshuavanderpoll/CVE-2025-14847](https://github.com/joshuavanderpoll/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/joshuavanderpoll/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/joshuavanderpoll/CVE-2025-14847.svg)
- [https://github.com/chinaxploiter/CVE-2025-14847-PoC](https://github.com/chinaxploiter/CVE-2025-14847-PoC) :  ![starts](https://img.shields.io/github/stars/chinaxploiter/CVE-2025-14847-PoC.svg) ![forks](https://img.shields.io/github/forks/chinaxploiter/CVE-2025-14847-PoC.svg)
- [https://github.com/Ashwesker/Ashwesker-CVE-2025-14847](https://github.com/Ashwesker/Ashwesker-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-14847.svg)
- [https://github.com/kuyrathdaro/cve-2025-14847](https://github.com/kuyrathdaro/cve-2025-14847) :  ![starts](https://img.shields.io/github/stars/kuyrathdaro/cve-2025-14847.svg) ![forks](https://img.shields.io/github/forks/kuyrathdaro/cve-2025-14847.svg)
- [https://github.com/lincemorado97/CVE-2025-14847](https://github.com/lincemorado97/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/lincemorado97/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/lincemorado97/CVE-2025-14847.svg)
- [https://github.com/Security-Phoenix-demo/mongobleed-exploit-CVE-2025-14847](https://github.com/Security-Phoenix-demo/mongobleed-exploit-CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/Security-Phoenix-demo/mongobleed-exploit-CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/Security-Phoenix-demo/mongobleed-exploit-CVE-2025-14847.svg)
- [https://github.com/tunahantekeoglu/MongoDeepDive](https://github.com/tunahantekeoglu/MongoDeepDive) :  ![starts](https://img.shields.io/github/stars/tunahantekeoglu/MongoDeepDive.svg) ![forks](https://img.shields.io/github/forks/tunahantekeoglu/MongoDeepDive.svg)
- [https://github.com/14mb1v45h/CYBERDUDEBIVASH-MONGODB-DETECTOR-v2026](https://github.com/14mb1v45h/CYBERDUDEBIVASH-MONGODB-DETECTOR-v2026) :  ![starts](https://img.shields.io/github/stars/14mb1v45h/CYBERDUDEBIVASH-MONGODB-DETECTOR-v2026.svg) ![forks](https://img.shields.io/github/forks/14mb1v45h/CYBERDUDEBIVASH-MONGODB-DETECTOR-v2026.svg)
- [https://github.com/ob1sec/mongobleeder](https://github.com/ob1sec/mongobleeder) :  ![starts](https://img.shields.io/github/stars/ob1sec/mongobleeder.svg) ![forks](https://img.shields.io/github/forks/ob1sec/mongobleeder.svg)


## CVE-2025-14733
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.5 and 2025.1 up to and including 2025.1.3.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-14733](https://github.com/Ashwesker/Ashwesker-CVE-2025-14733) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-14733.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-14733.svg)


## CVE-2025-14611
 Gladinet CentreStack and Triofox prior to version 16.12.10420.56791 used hardcoded values for their implementation of the AES cryptoscheme. This degrades security for public exposed endpoints that may make use of it and may offer arbitrary local file inclusion when provided a specially crafted request without authentication. This opens the door for future exploitation and can be leveraged with previous vulnerabilities to gain a full system compromise.

- [https://github.com/pl4tyz/CVE-2025-14611-CentreStack-and-Triofox-full-Poc-Exploit](https://github.com/pl4tyz/CVE-2025-14611-CentreStack-and-Triofox-full-Poc-Exploit) :  ![starts](https://img.shields.io/github/stars/pl4tyz/CVE-2025-14611-CentreStack-and-Triofox-full-Poc-Exploit.svg) ![forks](https://img.shields.io/github/forks/pl4tyz/CVE-2025-14611-CentreStack-and-Triofox-full-Poc-Exploit.svg)


## CVE-2025-13780
 pgAdmin versions up to 9.10 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-13780](https://github.com/Ashwesker/Ashwesker-CVE-2025-13780) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-13780.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-13780.svg)


## CVE-2025-13372
Django would like to thank Stackered for reporting this issue.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-13372](https://github.com/Ashwesker/Ashwesker-CVE-2025-13372) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-13372.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-13372.svg)


## CVE-2025-13315
 Twonky Server 8.5.2 on Linux and Windows is vulnerable to an access control flaw. An unauthenticated attacker can bypass web service API authentication controls to leak a log file and read the administrator's username and encrypted password.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-13315](https://github.com/Ashwesker/Ashwesker-CVE-2025-13315) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-13315.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-13315.svg)


## CVE-2025-12762
 pgAdmin versions up to 9.9 are affected by a Remote Code Execution (RCE) vulnerability that occurs when running in server mode and performing restores from PLAIN-format dump files. This issue allows attackers to inject and execute arbitrary commands on the server hosting pgAdmin, posing a critical risk to the integrity and security of the database management system and underlying data.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-12762](https://github.com/Ashwesker/Ashwesker-CVE-2025-12762) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-12762.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-12762.svg)


## CVE-2025-11953
 The Metro Development Server, which is opened by the React Native Community CLI, binds to external interfaces by default. The server exposes an endpoint that is vulnerable to OS command injection. This allows unauthenticated network attackers to send a POST request to the server and run arbitrary executables. On Windows, the attackers can also execute arbitrary shell commands with fully controlled arguments.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-11953](https://github.com/Ashwesker/Ashwesker-CVE-2025-11953) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-11953.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-11953.svg)


## CVE-2025-11001
The specific flaw exists within the handling of symbolic links in ZIP files. Crafted data in a ZIP file can cause the process to traverse to unintended directories. An attacker can leverage this vulnerability to execute code in the context of a service account. Was ZDI-CAN-26753.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-11001](https://github.com/Ashwesker/Ashwesker-CVE-2025-11001) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-11001.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-11001.svg)


## CVE-2025-10680
 OpenVPN 2.7_alpha1 through 2.7_beta1 on POSIX based platforms allows a remote authenticated server to inject shell commands via DNS variables when --dns-updown is in use

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-10680](https://github.com/Ashwesker/Ashwesker-CVE-2025-10680) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-10680.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-10680.svg)


## CVE-2025-10230
 A flaw was found in Samba, in the front-end WINS hook handling: NetBIOS names from registration packets are passed to a shell without proper validation or escaping. Unsanitized NetBIOS name data from WINS registration packets are inserted into a shell command and executed by the Samba Active Directory Domain Controller’s wins hook, allowing an unauthenticated network attacker to achieve remote command execution as the Samba process.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-10230](https://github.com/Ashwesker/Ashwesker-CVE-2025-10230) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-10230.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-10230.svg)


## CVE-2025-10035
 A deserialization vulnerability in the License Servlet of Fortra's GoAnywhere MFT allows an actor with a validly forged license response signature to deserialize an arbitrary actor-controlled object, possibly leading to command injection.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-10035](https://github.com/Ashwesker/Ashwesker-CVE-2025-10035) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-10035.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-10035.svg)


## CVE-2025-9961
This issue affects AX10 V1/V1.2/V2/V2.6/V3/V3.6: before 1.2.1; AX1500 V1/V1.20/V1.26/V1.60/V1.80/V2.60/V3.6: before 1.3.11.

- [https://github.com/yt2w/CVE-2025-9961](https://github.com/yt2w/CVE-2025-9961) :  ![starts](https://img.shields.io/github/stars/yt2w/CVE-2025-9961.svg) ![forks](https://img.shields.io/github/forks/yt2w/CVE-2025-9961.svg)


## CVE-2025-9242
 An Out-of-bounds Write vulnerability in WatchGuard Fireware OS may allow a remote unauthenticated attacker to execute arbitrary code. This vulnerability affects both the Mobile User VPN with IKEv2 and the Branch Office VPN using IKEv2 when configured with a dynamic gateway peer.This vulnerability affects Fireware OS 11.10.2 up to and including 11.12.4_Update1, 12.0 up to and including 12.11.3 and 2025.1.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-9242](https://github.com/Ashwesker/Ashwesker-CVE-2025-9242) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-9242.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-9242.svg)


## CVE-2025-8943
 The Custom MCPs feature is designed to execute OS commands, for instance, using tools like `npx` to spin up local MCP Servers. However, Flowise's inherent authentication and authorization model is minimal and lacks role-based access controls (RBAC). Furthermore, in Flowise versions before 3.0.1 the default installation operates without authentication unless explicitly configured. This combination allows unauthenticated network attackers to execute unsandboxed OS commands.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-8943](https://github.com/Ashwesker/Ashwesker-CVE-2025-8943) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-8943.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-8943.svg)


## CVE-2025-8110
 Improper Symbolic link handling in the PutContents API in Gogs allows Local Execution of Code.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-8110](https://github.com/Ashwesker/Ashwesker-CVE-2025-8110) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-8110.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-8110.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-8088](https://github.com/Ashwesker/Ashwesker-CVE-2025-8088) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-8088.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-8088.svg)


## CVE-2025-6389
 The Sneeit Framework plugin for WordPress is vulnerable to Remote Code Execution in all versions up to, and including, 8.3 via the sneeit_articles_pagination_callback() function. This is due to the function accepting user input and then passing that through call_user_func(). This makes it possible for unauthenticated attackers to execute code on the server which can be leveraged to inject backdoors or, for example, create new administrative user accounts.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-6389](https://github.com/Ashwesker/Ashwesker-CVE-2025-6389) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-6389.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-6389.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-6018](https://github.com/Ashwesker/Ashwesker-CVE-2025-6018) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-6018.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-6018.svg)


## CVE-2025-5777
 Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-5777](https://github.com/Ashwesker/Ashwesker-CVE-2025-5777) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-5777.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-5777.svg)


## CVE-2025-4403
 The Drag and Drop Multiple File Upload for WooCommerce plugin for WordPress is vulnerable to arbitrary file uploads in all versions up to, and including, 1.1.6 due to accepting a user‐supplied supported_type string and the uploaded filename without enforcing real extension or MIME checks within the upload() function. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-4403](https://github.com/Ashwesker/Ashwesker-CVE-2025-4403) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-4403.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-4403.svg)


## CVE-2025-4322
 The Motors theme for WordPress is vulnerable to privilege escalation via account takeover in all versions up to, and including, 5.6.67. This is due to the theme not properly validating a user's identity prior to updating their password. This makes it possible for unauthenticated attackers to change arbitrary user passwords, including those of administrators, and leverage that to gain access to their account.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-4322](https://github.com/Ashwesker/Ashwesker-CVE-2025-4322) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-4322.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-4322.svg)


## CVE-2025-4123
The default Content-Security-Policy (CSP) in Grafana will block the XSS though the `connect-src` directive.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-4123](https://github.com/Ashwesker/Ashwesker-CVE-2025-4123) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-4123.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-4123.svg)


## CVE-2025-3248
code.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-3248](https://github.com/Ashwesker/Ashwesker-CVE-2025-3248) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-3248.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-3248.svg)


## CVE-2025-2828
 A Server-Side Request Forgery (SSRF) vulnerability exists in the RequestsToolkit component of the langchain-community package (specifically, langchain_community.agent_toolkits.openapi.toolkit.RequestsToolkit) in langchain-ai/langchain version 0.0.27. This vulnerability occurs because the toolkit does not enforce restrictions on requests to remote internet addresses, allowing it to also access local addresses. As a result, an attacker could exploit this flaw to perform port scans, access local services, retrieve instance metadata from cloud environments (e.g., Azure, AWS), and interact with servers on the local network. This issue has been fixed in version 0.0.28.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-2828](https://github.com/Ashwesker/Ashwesker-CVE-2025-2828) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-2828.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-2828.svg)


## CVE-2025-2011
 The Slider & Popup Builder by Depicter plugin for WordPress is vulnerable to generic SQL Injection via the ‘s' parameter in all versions up to, and including, 3.6.1 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-2011](https://github.com/Ashwesker/Ashwesker-CVE-2025-2011) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-2011.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-2011.svg)


## CVE-2025-1974
 A security issue was discovered in Kubernetes where under certain conditions, an unauthenticated attacker with access to the pod network can achieve arbitrary code execution in the context of the ingress-nginx controller. This can lead to disclosure of Secrets accessible to the controller. (Note that in the default installation, the controller can access all Secrets cluster-wide.)

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-1974](https://github.com/Ashwesker/Ashwesker-CVE-2025-1974) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-1974.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-1974.svg)


## CVE-2025-1455
 The Royal Elementor Addons and Templates plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the Woo Grid widget in all versions up to, and including, 1.7.1012 due to insufficient input sanitization and output escaping. This makes it possible for authenticated attackers, with Contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-14558](https://github.com/Ashwesker/Ashwesker-CVE-2025-14558) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-14558.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-14558.svg)


## CVE-2025-1094
 Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-1094](https://github.com/Ashwesker/Ashwesker-CVE-2025-1094) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-1094.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-1094.svg)


## CVE-2025-0411
The specific flaw exists within the handling of archived files. When extracting files from a crafted archive that bears the Mark-of-the-Web, 7-Zip does not propagate the Mark-of-the-Web to the extracted files. An attacker can leverage this vulnerability to execute arbitrary code in the context of the current user. Was ZDI-CAN-25456.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-0411](https://github.com/Ashwesker/Ashwesker-CVE-2025-0411) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-0411.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-0411.svg)


## CVE-2025-0282
 A stack-based buffer overflow in Ivanti Connect Secure before version 22.7R2.5, Ivanti Policy Secure before version 22.7R1.2, and Ivanti Neurons for ZTA gateways before version 22.7R2.3 allows a remote unauthenticated attacker to achieve remote code execution.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-0282](https://github.com/Ashwesker/Ashwesker-CVE-2025-0282) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-0282.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-0282.svg)


## CVE-2025-0108
This issue does not affect Cloud NGFW or Prisma Access software.

- [https://github.com/Ashwesker/Ashwesker-CVE-2025-0108](https://github.com/Ashwesker/Ashwesker-CVE-2025-0108) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Ashwesker-CVE-2025-0108.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Ashwesker-CVE-2025-0108.svg)


## CVE-2024-52005
 Git is a source code management tool. When cloning from a server (or fetching, or pushing), informational or error messages are transported from the remote Git process to the client via the so-called "sideband channel". These messages will be prefixed with "remote:" and printed directly to the standard error output. Typically, this standard error output is connected to a terminal that understands ANSI escape sequences, which Git did not protect against. Most modern terminals support control sequences that can be used by a malicious actor to hide and misrepresent information, or to mislead the user into executing untrusted scripts. As requested on the git-security mailing list, the patches are under discussion on the public mailing list. Users are advised to update as soon as possible. Users unable to upgrade should avoid recursive clones unless they are from trusted sources.

- [https://github.com/andrewd-cg/cve-2024-52005-poc](https://github.com/andrewd-cg/cve-2024-52005-poc) :  ![starts](https://img.shields.io/github/stars/andrewd-cg/cve-2024-52005-poc.svg) ![forks](https://img.shields.io/github/forks/andrewd-cg/cve-2024-52005-poc.svg)


## CVE-2024-44083
 ida64.dll in Hex-Rays IDA Pro through 8.4 crashes when there is a section that has many jumps linked, and the final jump corresponds to the payload from where the actual entry point will be invoked. NOTE: in many use cases, this is an inconvenience but not a security issue.

- [https://github.com/dynamicx64/CVE-2024-44083](https://github.com/dynamicx64/CVE-2024-44083) :  ![starts](https://img.shields.io/github/stars/dynamicx64/CVE-2024-44083.svg) ![forks](https://img.shields.io/github/forks/dynamicx64/CVE-2024-44083.svg)


## CVE-2023-45158
 An OS command injection vulnerability exists in web2py 2.24.1 and earlier. When the product is configured to use notifySendHandler for logging (not the default configuration), a crafted web request may execute an arbitrary OS command on the web server using the product.

- [https://github.com/yifanzhg/CVE-2023-45158](https://github.com/yifanzhg/CVE-2023-45158) :  ![starts](https://img.shields.io/github/stars/yifanzhg/CVE-2023-45158.svg) ![forks](https://img.shields.io/github/forks/yifanzhg/CVE-2023-45158.svg)


## CVE-2023-38831
 RARLAB WinRAR before 6.23 allows attackers to execute arbitrary code when a user attempts to view a benign file within a ZIP archive. The issue occurs because a ZIP archive may include a benign file (such as an ordinary .JPG file) and also a folder that has the same name as the benign file, and the contents of the folder (which may include executable content) are processed during an attempt to access only the benign file. This was exploited in the wild in April through October 2023.

- [https://github.com/kuyrathdaro/cve-2023-38831](https://github.com/kuyrathdaro/cve-2023-38831) :  ![starts](https://img.shields.io/github/stars/kuyrathdaro/cve-2023-38831.svg) ![forks](https://img.shields.io/github/forks/kuyrathdaro/cve-2023-38831.svg)


## CVE-2023-3287
 A BOLA vulnerability in POST /admins allows a low privileged user to create a high privileged user (admin) in the system. This results in privilege escalation.

- [https://github.com/AntonieSoga/BOLA-PoC_CVE-2023-3287](https://github.com/AntonieSoga/BOLA-PoC_CVE-2023-3287) :  ![starts](https://img.shields.io/github/stars/AntonieSoga/BOLA-PoC_CVE-2023-3287.svg) ![forks](https://img.shields.io/github/forks/AntonieSoga/BOLA-PoC_CVE-2023-3287.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Karararam/SpringBoot-Exploit-Toolkit](https://github.com/Karararam/SpringBoot-Exploit-Toolkit) :  ![starts](https://img.shields.io/github/stars/Karararam/SpringBoot-Exploit-Toolkit.svg) ![forks](https://img.shields.io/github/forks/Karararam/SpringBoot-Exploit-Toolkit.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Taldrid1/cve-2021-41773](https://github.com/Taldrid1/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/Taldrid1/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Taldrid1/cve-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)
- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)
- [https://github.com/vuongnv3389-sec/cve-2021-41773](https://github.com/vuongnv3389-sec/cve-2021-41773) :  ![starts](https://img.shields.io/github/stars/vuongnv3389-sec/cve-2021-41773.svg) ![forks](https://img.shields.io/github/forks/vuongnv3389-sec/cve-2021-41773.svg)


## CVE-2021-2220
 Vulnerability in the PeopleSoft Enterprise SCM eProcurement product of Oracle PeopleSoft (component: Manage Requisition Status). The supported version that is affected is 9.2. Easily exploitable vulnerability allows low privileged attacker with network access via HTTP to compromise PeopleSoft Enterprise SCM eProcurement. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of PeopleSoft Enterprise SCM eProcurement accessible data as well as unauthorized read access to a subset of PeopleSoft Enterprise SCM eProcurement accessible data. CVSS 3.1 Base Score 5.4 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/nyambiblaise/Exfiltrated-Machine-Walkthrough---Subrion-CMS-CVE-2021-2220-](https://github.com/nyambiblaise/Exfiltrated-Machine-Walkthrough---Subrion-CMS-CVE-2021-2220-) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/Exfiltrated-Machine-Walkthrough---Subrion-CMS-CVE-2021-2220-.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/Exfiltrated-Machine-Walkthrough---Subrion-CMS-CVE-2021-2220-.svg)


## CVE-2020-15778
 scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."

- [https://github.com/yifanzhg/CVE-2020-15778](https://github.com/yifanzhg/CVE-2020-15778) :  ![starts](https://img.shields.io/github/stars/yifanzhg/CVE-2020-15778.svg) ![forks](https://img.shields.io/github/forks/yifanzhg/CVE-2020-15778.svg)


## CVE-2020-0796
 A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.

- [https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE](https://github.com/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE) :  ![starts](https://img.shields.io/github/stars/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg) ![forks](https://img.shields.io/github/forks/nyambiblaise/Microsoft-Windows-SMBGhost-Vulnerability-Checker---CVE-2020-0796---SMBv3-RCE.svg)


## CVE-2018-8581
 An elevation of privilege vulnerability exists in Microsoft Exchange Server, aka "Microsoft Exchange Server Elevation of Privilege Vulnerability." This affects Microsoft Exchange Server.

- [https://github.com/Pranjal6955/CVE-2018-8581-testing](https://github.com/Pranjal6955/CVE-2018-8581-testing) :  ![starts](https://img.shields.io/github/stars/Pranjal6955/CVE-2018-8581-testing.svg) ![forks](https://img.shields.io/github/forks/Pranjal6955/CVE-2018-8581-testing.svg)

