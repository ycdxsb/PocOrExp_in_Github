# Update 2025-12-27
## CVE-2025-68645
 A Local File Inclusion (LFI) vulnerability exists in the Webmail Classic UI of Zimbra Collaboration (ZCS) 10.0 and 10.1 because of improper handling of user-supplied request parameters in the RestFilter servlet. An unauthenticated remote attacker can craft requests to the /h/rest endpoint to influence internal request dispatching, allowing inclusion of arbitrary files from the WebRoot directory.

- [https://github.com/Ashwesker/Blackash-CVE-2025-68645](https://github.com/Ashwesker/Blackash-CVE-2025-68645) :  ![starts](https://img.shields.io/github/stars/Ashwesker/Blackash-CVE-2025-68645.svg) ![forks](https://img.shields.io/github/forks/Ashwesker/Blackash-CVE-2025-68645.svg)


## CVE-2025-68613
 n8n is an open source workflow automation platform. Versions starting with 0.211.0 and prior to 1.120.4, 1.121.1, and 1.122.0 contain a critical Remote Code Execution (RCE) vulnerability in their workflow expression evaluation system. Under certain conditions, expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying runtime. An authenticated attacker could abuse this behavior to execute arbitrary code with the privileges of the n8n process. Successful exploitation may lead to full compromise of the affected instance, including unauthorized access to sensitive data, modification of workflows, and execution of system-level operations. This issue has been fixed in versions 1.120.4, 1.121.1, and 1.122.0. Users are strongly advised to upgrade to a patched version, which introduces additional safeguards to restrict expression evaluation. If upgrading is not immediately possible, administrators should consider the following temporary mitigations: Limit workflow creation and editing permissions to fully trusted users only; and/or deploy n8n in a hardened environment with restricted operating system privileges and network access to reduce the impact of potential exploitation. These workarounds do not fully eliminate the risk and should only be used as short-term measures.

- [https://github.com/mbanyamer/n8n-Authenticated-Expression-Injection-RCE-CVE-2025-68613](https://github.com/mbanyamer/n8n-Authenticated-Expression-Injection-RCE-CVE-2025-68613) :  ![starts](https://img.shields.io/github/stars/mbanyamer/n8n-Authenticated-Expression-Injection-RCE-CVE-2025-68613.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/n8n-Authenticated-Expression-Injection-RCE-CVE-2025-68613.svg)
- [https://github.com/hackersatyamrastogi/n8n-exploit-CVE-2025-68613-n8n-God-Mode-Ultimate](https://github.com/hackersatyamrastogi/n8n-exploit-CVE-2025-68613-n8n-God-Mode-Ultimate) :  ![starts](https://img.shields.io/github/stars/hackersatyamrastogi/n8n-exploit-CVE-2025-68613-n8n-God-Mode-Ultimate.svg) ![forks](https://img.shields.io/github/forks/hackersatyamrastogi/n8n-exploit-CVE-2025-68613-n8n-God-Mode-Ultimate.svg)
- [https://github.com/JohannesLks/CVE-2025-68613-Python-Exploit](https://github.com/JohannesLks/CVE-2025-68613-Python-Exploit) :  ![starts](https://img.shields.io/github/stars/JohannesLks/CVE-2025-68613-Python-Exploit.svg) ![forks](https://img.shields.io/github/forks/JohannesLks/CVE-2025-68613-Python-Exploit.svg)
- [https://github.com/AbdulRKB/n8n-RCE](https://github.com/AbdulRKB/n8n-RCE) :  ![starts](https://img.shields.io/github/stars/AbdulRKB/n8n-RCE.svg) ![forks](https://img.shields.io/github/forks/AbdulRKB/n8n-RCE.svg)


## CVE-2025-62726
 n8n is an open source workflow automation platform. Prior to 1.113.0, a remote code execution vulnerability exists in the Git Node component available in both Cloud and Self-Hosted versions of n8n. When a malicious actor clones a remote repository containing a pre-commit hook, the subsequent use of the Commit operation in the Git Node can inadvertently trigger the hook’s execution. This allows attackers to execute arbitrary code within the n8n environment, potentially compromising the system and any connected credentials or workflows. This vulnerability is fixed in 1.113.0.

- [https://github.com/Muzyli/cve-2025-62726-malicious-repo](https://github.com/Muzyli/cve-2025-62726-malicious-repo) :  ![starts](https://img.shields.io/github/stars/Muzyli/cve-2025-62726-malicious-repo.svg) ![forks](https://img.shields.io/github/forks/Muzyli/cve-2025-62726-malicious-repo.svg)


## CVE-2025-59532
 Codex CLI is a coding agent from OpenAI that runs locally. In versions 0.2.0 to 0.38.0, due to a bug in the sandbox configuration logic, Codex CLI could treat a model-generated cwd as the sandbox’s writable root, including paths outside of the folder where the user started their session. This logic bypassed the intended workspace boundary and enables arbitrary file writes and command execution where the Codex process has permissions - this did not impact the network-disabled sandbox restriction. This issue has been patched in Codex CLI 0.39.0 that canonicalizes and validates that the boundary used for sandbox policy is based on where the user started the session, and not the one generated by the model. Users running 0.38.0 or earlier should update immediately via their package manager or by reinstalling the latest Codex CLI to ensure sandbox boundaries are enforced. If using the Codex IDE extension, users should immediately update to 0.4.12 for a fix of the sandbox issue.

- [https://github.com/baktistr/cve-2025-59532-poc](https://github.com/baktistr/cve-2025-59532-poc) :  ![starts](https://img.shields.io/github/stars/baktistr/cve-2025-59532-poc.svg) ![forks](https://img.shields.io/github/forks/baktistr/cve-2025-59532-poc.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/vijay-shirhatti/RSC-Detect-CVE-2025-55182](https://github.com/vijay-shirhatti/RSC-Detect-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/vijay-shirhatti/RSC-Detect-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/vijay-shirhatti/RSC-Detect-CVE-2025-55182.svg)
- [https://github.com/chrahman/react2shell-CVE-2025-55182-full-rce-script](https://github.com/chrahman/react2shell-CVE-2025-55182-full-rce-script) :  ![starts](https://img.shields.io/github/stars/chrahman/react2shell-CVE-2025-55182-full-rce-script.svg) ![forks](https://img.shields.io/github/forks/chrahman/react2shell-CVE-2025-55182-full-rce-script.svg)
- [https://github.com/rix4uni/CVE-2025-55182](https://github.com/rix4uni/CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/rix4uni/CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/rix4uni/CVE-2025-55182.svg)


## CVE-2025-49844
 Redis is an open source, in-memory database that persists on disk. Versions 8.2.1 and below allow an authenticated user to use a specially crafted Lua script to manipulate the garbage collector, trigger a use-after-free and potentially lead to remote code execution. The problem exists in all versions of Redis with Lua scripting. This issue is fixed in version 8.2.2. To workaround this issue without patching the redis-server executable is to prevent users from executing Lua scripts. This can be done using ACL to restrict EVAL and EVALSHA commands.

- [https://github.com/hzhsec/redis-cve_2025_49844](https://github.com/hzhsec/redis-cve_2025_49844) :  ![starts](https://img.shields.io/github/stars/hzhsec/redis-cve_2025_49844.svg) ![forks](https://img.shields.io/github/forks/hzhsec/redis-cve_2025_49844.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/Mr-Alperen/CVE-2025-32463](https://github.com/Mr-Alperen/CVE-2025-32463) :  ![starts](https://img.shields.io/github/stars/Mr-Alperen/CVE-2025-32463.svg) ![forks](https://img.shields.io/github/forks/Mr-Alperen/CVE-2025-32463.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/OffSecPlaybook/CVE-2025-32462-](https://github.com/OffSecPlaybook/CVE-2025-32462-) :  ![starts](https://img.shields.io/github/stars/OffSecPlaybook/CVE-2025-32462-.svg) ![forks](https://img.shields.io/github/forks/OffSecPlaybook/CVE-2025-32462-.svg)


## CVE-2025-32433
 Erlang/OTP is a set of libraries for the Erlang programming language. Prior to versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20, a SSH server may allow an attacker to perform unauthenticated remote code execution (RCE). By exploiting a flaw in SSH protocol message handling, a malicious actor could gain unauthorized access to affected systems and execute arbitrary commands without valid credentials. This issue is patched in versions OTP-27.3.3, OTP-26.2.5.11, and OTP-25.3.2.20. A temporary workaround involves disabling the SSH server or to prevent access via firewall rules.

- [https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit](https://github.com/giriaryan694-a11y/cve-2025-32433_rce_exploit) :  ![starts](https://img.shields.io/github/stars/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg) ![forks](https://img.shields.io/github/forks/giriaryan694-a11y/cve-2025-32433_rce_exploit.svg)


## CVE-2025-30208
 Vite, a provider of frontend development tooling, has a vulnerability in versions prior to 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10. `@fs` denies access to files outside of Vite serving allow list. Adding `?raw??` or `?import&raw??` to the URL bypasses this limitation and returns the file content if it exists. This bypass exists because trailing separators such as `?` are removed in several places, but are not accounted for in query string regexes. The contents of arbitrary files can be returned to the browser. Only apps explicitly exposing the Vite dev server to the network (using `--host` or `server.host` config option) are affected. Versions 6.2.3, 6.1.2, 6.0.12, 5.4.15, and 4.5.10 fix the issue.

- [https://github.com/layanOd/CVE-2025-30208-Arbitrary-File-Read-in-Vite-servers](https://github.com/layanOd/CVE-2025-30208-Arbitrary-File-Read-in-Vite-servers) :  ![starts](https://img.shields.io/github/stars/layanOd/CVE-2025-30208-Arbitrary-File-Read-in-Vite-servers.svg) ![forks](https://img.shields.io/github/forks/layanOd/CVE-2025-30208-Arbitrary-File-Read-in-Vite-servers.svg)


## CVE-2025-14766
 Out of bounds read and write in V8 in Google Chrome prior to 143.0.7499.147 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766](https://github.com/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766) :  ![starts](https://img.shields.io/github/stars/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766.svg) ![forks](https://img.shields.io/github/forks/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766.svg)


## CVE-2025-14765
 Use after free in WebGPU in Google Chrome prior to 143.0.7499.147 allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766](https://github.com/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766) :  ![starts](https://img.shields.io/github/stars/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766.svg) ![forks](https://img.shields.io/github/forks/InfoSecAntara/CVE-2025-14765-and-CVE-2025-14766.svg)


## CVE-2025-6934
 The Opal Estate Pro – Property Management and Submission plugin for WordPress, used by the FullHouse - Real Estate Responsive WordPress Theme, is vulnerable to privilege escalation via in all versions up to, and including, 1.7.5. This is due to a lack of role restriction during registration in the 'on_regiser_user' function. This makes it possible for unauthenticated attackers to arbitrarily choose the role, including the Administrator role, assigned when registering.

- [https://github.com/luxzy28/CVE-2025-6934](https://github.com/luxzy28/CVE-2025-6934) :  ![starts](https://img.shields.io/github/stars/luxzy28/CVE-2025-6934.svg) ![forks](https://img.shields.io/github/forks/luxzy28/CVE-2025-6934.svg)
- [https://github.com/luxzy28/CVE-2025-6934.yaml](https://github.com/luxzy28/CVE-2025-6934.yaml) :  ![starts](https://img.shields.io/github/stars/luxzy28/CVE-2025-6934.yaml.svg) ![forks](https://img.shields.io/github/forks/luxzy28/CVE-2025-6934.yaml.svg)


## CVE-2025-3446
 Mattermost versions 10.6.x = 10.6.1, 10.5.x = 10.5.2, 10.4.x = 10.4.4, 9.11.x = 9.11.11 fail to check the correct permissions which allows authenticated users who only have permission to invite non-guest users to a team to add guest users to that team via the API to add a single user to a team.

- [https://github.com/NSM-Barii/CVE-2025-34462](https://github.com/NSM-Barii/CVE-2025-34462) :  ![starts](https://img.shields.io/github/stars/NSM-Barii/CVE-2025-34462.svg) ![forks](https://img.shields.io/github/forks/NSM-Barii/CVE-2025-34462.svg)


## CVE-2024-28397
 An issue in the component js2py.disable_pyimport() of js2py up to v0.74 allows attackers to execute arbitrary code via a crafted API call.

- [https://github.com/releaseown/exploit-js2py](https://github.com/releaseown/exploit-js2py) :  ![starts](https://img.shields.io/github/stars/releaseown/exploit-js2py.svg) ![forks](https://img.shields.io/github/forks/releaseown/exploit-js2py.svg)


## CVE-2024-1900
The user will stay authenticated until the Devolutions Server token expiration.

- [https://github.com/adminlove520/cve-2024-19002](https://github.com/adminlove520/cve-2024-19002) :  ![starts](https://img.shields.io/github/stars/adminlove520/cve-2024-19002.svg) ![forks](https://img.shields.io/github/forks/adminlove520/cve-2024-19002.svg)


## CVE-2024-0204
 Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.

- [https://github.com/adminlove520/CVE-2024-0204](https://github.com/adminlove520/CVE-2024-0204) :  ![starts](https://img.shields.io/github/stars/adminlove520/CVE-2024-0204.svg) ![forks](https://img.shields.io/github/forks/adminlove520/CVE-2024-0204.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/KirolosKhairy/CVE-2023-27372](https://github.com/KirolosKhairy/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/KirolosKhairy/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/KirolosKhairy/CVE-2023-27372.svg)


## CVE-2023-22527
Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian’s January Security Bulletin.

- [https://github.com/adminlove520/CVE-2023-22527](https://github.com/adminlove520/CVE-2023-22527) :  ![starts](https://img.shields.io/github/stars/adminlove520/CVE-2023-22527.svg) ![forks](https://img.shields.io/github/forks/adminlove520/CVE-2023-22527.svg)


## CVE-2003-0201
 Buffer overflow in the call_trans2open function in trans2.c for Samba 2.2.x before 2.2.8a, 2.0.10 and earlier 2.0.x versions, and Samba-TNG before 0.3.2, allows remote attackers to execute arbitrary code.

- [https://github.com/deepakkcybersec-eng/Kioptrix-Level1-Vulnerability-Analysis](https://github.com/deepakkcybersec-eng/Kioptrix-Level1-Vulnerability-Analysis) :  ![starts](https://img.shields.io/github/stars/deepakkcybersec-eng/Kioptrix-Level1-Vulnerability-Analysis.svg) ![forks](https://img.shields.io/github/forks/deepakkcybersec-eng/Kioptrix-Level1-Vulnerability-Analysis.svg)

