# Update 2026-05-20
## CVE-2026-45321
 On 2026-05-11, between approximately 19:20 and 19:26 UTC, 84 malicious versions across 42 @tanstack/* packages were published to the npm registry. The publishes were authenticated via the legitimate GitHub Actions OIDC trusted-publisher binding for TanStack/router, but the publish workflow itself was not modified. The attacker chained three known vulnerability classes — a pull_request_target "Pwn Request" misconfiguration, GitHub Actions cache poisoning across the fork↔base trust boundary, and runtime memory extraction of the OIDC token from the Actions runner process — to publish credential-stealing malware under a trusted identity. Each affected package received exactly two malicious versions, published a few minutes apart.

- [https://github.com/nkopylov/tanscript-exploit-check](https://github.com/nkopylov/tanscript-exploit-check) :  ![starts](https://img.shields.io/github/stars/nkopylov/tanscript-exploit-check.svg) ![forks](https://img.shields.io/github/forks/nkopylov/tanscript-exploit-check.svg)


## CVE-2026-43500
page_pool RX, GRO).  The OOM/trace handling already in place is reused.

- [https://github.com/First-John/CVE-2026-43500](https://github.com/First-John/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/First-John/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/First-John/CVE-2026-43500.svg)


## CVE-2026-43284
destination-frag path or fall back to skb_cow_data().

- [https://github.com/ochebotar/copy-fail-CVE-2026-31431-detection-probe](https://github.com/ochebotar/copy-fail-CVE-2026-31431-detection-probe) :  ![starts](https://img.shields.io/github/stars/ochebotar/copy-fail-CVE-2026-31431-detection-probe.svg) ![forks](https://img.shields.io/github/forks/ochebotar/copy-fail-CVE-2026-31431-detection-probe.svg)
- [https://github.com/First-John/CVE-2026-43500](https://github.com/First-John/CVE-2026-43500) :  ![starts](https://img.shields.io/github/stars/First-John/CVE-2026-43500.svg) ![forks](https://img.shields.io/github/forks/First-John/CVE-2026-43500.svg)
- [https://github.com/DXC-0/linux-lpe-sigma](https://github.com/DXC-0/linux-lpe-sigma) :  ![starts](https://img.shields.io/github/stars/DXC-0/linux-lpe-sigma.svg) ![forks](https://img.shields.io/github/forks/DXC-0/linux-lpe-sigma.svg)


## CVE-2026-42945
 NGINX Plus and NGINX Open Source have a vulnerability in the ngx_http_rewrite_module module. This vulnerability exists when the rewrite directive is followed by a rewrite, if, or set directive and an unnamed Perl-Compatible Regular Expression (PCRE) capture (for example, $1, $2) with a replacement string that includes a question mark (?). An unauthenticated attacker along with conditions beyond its control can exploit this vulnerability by sending crafted HTTP requests. This may cause a heap buffer overflow in the NGINX worker process leading to a restart. Additionally, for systems with Address Space Layout Randomization (ASLR ) disabled, code execution is possible.  Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated.

- [https://github.com/hnytgl/cve-2026-42945](https://github.com/hnytgl/cve-2026-42945) :  ![starts](https://img.shields.io/github/stars/hnytgl/cve-2026-42945.svg) ![forks](https://img.shields.io/github/forks/hnytgl/cve-2026-42945.svg)


## CVE-2026-41096
 Heap-based buffer overflow in Microsoft Windows DNS allows an unauthorized attacker to execute code over a network.

- [https://github.com/CryptReaper12/CVE-2026-41096](https://github.com/CryptReaper12/CVE-2026-41096) :  ![starts](https://img.shields.io/github/stars/CryptReaper12/CVE-2026-41096.svg) ![forks](https://img.shields.io/github/forks/CryptReaper12/CVE-2026-41096.svg)


## CVE-2026-39636
 Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') vulnerability in livemesh Livemesh Addons for Elementor addons-for-elementor allows Stored XSS.This issue affects Livemesh Addons for Elementor: from n/a through = 9.0.

- [https://github.com/CatchCatOoO/CVE-2026-39636-vulnerability-exp](https://github.com/CatchCatOoO/CVE-2026-39636-vulnerability-exp) :  ![starts](https://img.shields.io/github/stars/CatchCatOoO/CVE-2026-39636-vulnerability-exp.svg) ![forks](https://img.shields.io/github/forks/CatchCatOoO/CVE-2026-39636-vulnerability-exp.svg)


## CVE-2026-36438
 An issue in Intelbras VIP-1230-D-G4 Version V2.800.00IB00C.0.T allows a remote attacker to obtain sensitive information via password reset functionality under /OutsideCmd

- [https://github.com/kensh1k/CVE-2026-36438](https://github.com/kensh1k/CVE-2026-36438) :  ![starts](https://img.shields.io/github/stars/kensh1k/CVE-2026-36438.svg) ![forks](https://img.shields.io/github/forks/kensh1k/CVE-2026-36438.svg)


## CVE-2026-34197
Users are recommended to upgrade to version 5.19.4 or 6.2.3, which fixes the issue

- [https://github.com/hnytgl/cve-2026-34197](https://github.com/hnytgl/cve-2026-34197) :  ![starts](https://img.shields.io/github/stars/hnytgl/cve-2026-34197.svg) ![forks](https://img.shields.io/github/forks/hnytgl/cve-2026-34197.svg)
- [https://github.com/LAT-06/CVE-2026-34197](https://github.com/LAT-06/CVE-2026-34197) :  ![starts](https://img.shields.io/github/stars/LAT-06/CVE-2026-34197.svg) ![forks](https://img.shields.io/github/forks/LAT-06/CVE-2026-34197.svg)


## CVE-2026-33825
 Insufficient granularity of access control in Microsoft Defender allows an authorized attacker to elevate privileges locally.

- [https://github.com/0xBlackash/CVE-2026-33825](https://github.com/0xBlackash/CVE-2026-33825) :  ![starts](https://img.shields.io/github/stars/0xBlackash/CVE-2026-33825.svg) ![forks](https://img.shields.io/github/forks/0xBlackash/CVE-2026-33825.svg)


## CVE-2026-33824
 Double free in Windows IKE Extension allows an unauthorized attacker to execute code over a network.

- [https://github.com/EpSiLoNPoInTOrI/IKEV2-POC](https://github.com/EpSiLoNPoInTOrI/IKEV2-POC) :  ![starts](https://img.shields.io/github/stars/EpSiLoNPoInTOrI/IKEV2-POC.svg) ![forks](https://img.shields.io/github/forks/EpSiLoNPoInTOrI/IKEV2-POC.svg)


## CVE-2026-32683
 Some EZVIZ products utilize older versions of cloud feature modules with legacy API interfaces, which pose a data transmission risk. Attackers can exploit this by eavesdropping on network requests to obtain data.Users are advised to upgrade the app to the latest version and enable the video encryption feature.

- [https://github.com/ByteWraith1/CVE-2026-32683](https://github.com/ByteWraith1/CVE-2026-32683) :  ![starts](https://img.shields.io/github/stars/ByteWraith1/CVE-2026-32683.svg) ![forks](https://img.shields.io/github/forks/ByteWraith1/CVE-2026-32683.svg)


## CVE-2026-31431
AD directly.

- [https://github.com/4xura/CVE-2026-31431-Copy-Fail](https://github.com/4xura/CVE-2026-31431-Copy-Fail) :  ![starts](https://img.shields.io/github/stars/4xura/CVE-2026-31431-Copy-Fail.svg) ![forks](https://img.shields.io/github/forks/4xura/CVE-2026-31431-Copy-Fail.svg)
- [https://github.com/yuspring/cve-2026-31431-poc](https://github.com/yuspring/cve-2026-31431-poc) :  ![starts](https://img.shields.io/github/stars/yuspring/cve-2026-31431-poc.svg) ![forks](https://img.shields.io/github/forks/yuspring/cve-2026-31431-poc.svg)
- [https://github.com/guiimoraes/CVE-2026-31431](https://github.com/guiimoraes/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/guiimoraes/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/guiimoraes/CVE-2026-31431.svg)
- [https://github.com/insomnisec/Detections-CVE-2026-31431](https://github.com/insomnisec/Detections-CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/insomnisec/Detections-CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/insomnisec/Detections-CVE-2026-31431.svg)
- [https://github.com/adityasingh108/CVE-2026-31431-Metasploit-exploit](https://github.com/adityasingh108/CVE-2026-31431-Metasploit-exploit) :  ![starts](https://img.shields.io/github/stars/adityasingh108/CVE-2026-31431-Metasploit-exploit.svg) ![forks](https://img.shields.io/github/forks/adityasingh108/CVE-2026-31431-Metasploit-exploit.svg)
- [https://github.com/devstuff/harden-docker-seccomp](https://github.com/devstuff/harden-docker-seccomp) :  ![starts](https://img.shields.io/github/stars/devstuff/harden-docker-seccomp.svg) ![forks](https://img.shields.io/github/forks/devstuff/harden-docker-seccomp.svg)
- [https://github.com/abdullaabdullazade/CVE-2026-31431](https://github.com/abdullaabdullazade/CVE-2026-31431) :  ![starts](https://img.shields.io/github/stars/abdullaabdullazade/CVE-2026-31431.svg) ![forks](https://img.shields.io/github/forks/abdullaabdullazade/CVE-2026-31431.svg)


## CVE-2026-8053
This issue impacts MongoDB Server v5.0 versions prior to 5.0.33, v6.0 versions prior to 6.0.28, v7.0 versions prior to 7.0.34, v8.0 versions prior to 8.0.23, v8.2 versions prior to 8.2.9 and v8.3 versions prior to 8.3.2.

- [https://github.com/mgiay/CVE-2026-8053-MongoDB](https://github.com/mgiay/CVE-2026-8053-MongoDB) :  ![starts](https://img.shields.io/github/stars/mgiay/CVE-2026-8053-MongoDB.svg) ![forks](https://img.shields.io/github/forks/mgiay/CVE-2026-8053-MongoDB.svg)


## CVE-2026-6379
 The WP Photo Album Plus WordPress plugin before 9.1.11.001 does not properly sanitize and escape a parameter before using it in a SQL query, allowing unauthenticated users to perform SQL injection attacks.

- [https://github.com/dinosn/cve-2026-6379](https://github.com/dinosn/cve-2026-6379) :  ![starts](https://img.shields.io/github/stars/dinosn/cve-2026-6379.svg) ![forks](https://img.shields.io/github/forks/dinosn/cve-2026-6379.svg)


## CVE-2026-5203
 A vulnerability was found in CMS Made Simple up to 2.2.22. This impacts the function _copyFilesToFolder in the library modules/UserGuide/lib/class.UserGuideImporterExporter.php of the component UserGuide Module XML Import. The manipulation results in path traversal. It is possible to launch the attack remotely. The exploit has been made public and could be used. This issue has been reported early to the project. They confirmed, that "this has already been discovered and fixed for the next release."

- [https://github.com/CaginKyr/CVE-2026-5203](https://github.com/CaginKyr/CVE-2026-5203) :  ![starts](https://img.shields.io/github/stars/CaginKyr/CVE-2026-5203.svg) ![forks](https://img.shields.io/github/forks/CaginKyr/CVE-2026-5203.svg)


## CVE-2026-0596
 A command injection vulnerability exists in mlflow/mlflow when serving a model with `enable_mlserver=True`. The `model_uri` is embedded directly into a shell command executed via `bash -c` without proper sanitization. If the `model_uri` contains shell metacharacters, such as `$()` or backticks, it allows for command substitution and execution of attacker-controlled commands. This vulnerability affects the latest version of mlflow/mlflow and can lead to privilege escalation if a higher-privileged service serves models from a directory writable by lower-privileged users.

- [https://github.com/SparshBiswas-AI/CVE-2026-0596-Reproduction](https://github.com/SparshBiswas-AI/CVE-2026-0596-Reproduction) :  ![starts](https://img.shields.io/github/stars/SparshBiswas-AI/CVE-2026-0596-Reproduction.svg) ![forks](https://img.shields.io/github/forks/SparshBiswas-AI/CVE-2026-0596-Reproduction.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-](https://github.com/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-) :  ![starts](https://img.shields.io/github/stars/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-.svg) ![forks](https://img.shields.io/github/forks/raivenLockdown/RCE_React2Shell_ButCooler-SomeUselessUsefulThingsLMAO-.svg)
- [https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182](https://github.com/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182) :  ![starts](https://img.shields.io/github/stars/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg) ![forks](https://img.shields.io/github/forks/MuhammadWaseem29/React2Shell_Rce-cve-2025-55182.svg)


## CVE-2025-34291
 Langflow versions up to and including 1.6.9 contain a chained vulnerability that enables account takeover and remote code execution. An overly permissive CORS configuration (allow_origins='*' with allow_credentials=True) combined with a refresh token cookie configured as SameSite=None allows a malicious webpage to perform cross-origin requests that include credentials and successfully call the refresh endpoint. An attacker-controlled origin can therefore obtain fresh access_token / refresh_token pairs for a victim session. Obtained tokens permit access to authenticated endpoints — including built-in code-execution functionality — allowing the attacker to execute arbitrary code and achieve full system compromise.

- [https://github.com/amnnrth/CVE-2025-34291_cors_security_scanner](https://github.com/amnnrth/CVE-2025-34291_cors_security_scanner) :  ![starts](https://img.shields.io/github/stars/amnnrth/CVE-2025-34291_cors_security_scanner.svg) ![forks](https://img.shields.io/github/forks/amnnrth/CVE-2025-34291_cors_security_scanner.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/MKIRAHMET/CVE-2025-29927-PoC](https://github.com/MKIRAHMET/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/MKIRAHMET/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/MKIRAHMET/CVE-2025-29927-PoC.svg)


## CVE-2025-20260
This vulnerability exists because memory buffers are allocated incorrectly when PDF files are processed. An attacker could exploit this vulnerability by submitting a crafted PDF file to be scanned by ClamAV on an affected device. A successful exploit could allow the attacker to trigger a buffer overflow, likely resulting in the termination of the ClamAV scanning process and a DoS condition on the affected software. Although unproven, there is also a possibility that an attacker could leverage the buffer overflow to execute arbitrary code with the privileges of the ClamAV process.

- [https://github.com/Alex-Acero-Security/CVE-2025-20260-POC](https://github.com/Alex-Acero-Security/CVE-2025-20260-POC) :  ![starts](https://img.shields.io/github/stars/Alex-Acero-Security/CVE-2025-20260-POC.svg) ![forks](https://img.shields.io/github/forks/Alex-Acero-Security/CVE-2025-20260-POC.svg)


## CVE-2025-14177
 In PHP versions:8.1.* before 8.1.34, 8.2.* before 8.2.30, 8.3.* before 8.3.29, 8.4.* before 8.4.16, 8.5.* before 8.5.1, the getimagesize() function may leak uninitialized heap memory into the APPn segments (e.g., APP1) when reading images in multi-chunk mode (such as via php://filter). This occurs due to a bug in php_read_stream_all_chunks() that overwrites the buffer without advancing the pointer, leaving tail bytes uninitialized. This may lead to information disclosure of sensitive heap data and affect the confidentiality of the target server.

- [https://github.com/34zY/CVE-2025-14177](https://github.com/34zY/CVE-2025-14177) :  ![starts](https://img.shields.io/github/stars/34zY/CVE-2025-14177.svg) ![forks](https://img.shields.io/github/forks/34zY/CVE-2025-14177.svg)


## CVE-2025-11203
The specific flaw exists within the handling of the API_KEY parameter provided to the health endpoint. The issue results from exposing sensitive information to an unauthorized actor. An attacker can leverage this vulnerability to disclose stored credentials, leading to further compromise. Was ZDI-CAN-26585.

- [https://github.com/learner202649/CVE-2025-11203-PoC](https://github.com/learner202649/CVE-2025-11203-PoC) :  ![starts](https://img.shields.io/github/stars/learner202649/CVE-2025-11203-PoC.svg) ![forks](https://img.shields.io/github/forks/learner202649/CVE-2025-11203-PoC.svg)


## CVE-2024-51358
 An issue in Linux Server Heimdall v.2.6.1 allows a remote attacker to execute arbitrary code via a crafted script to the Add new application.

- [https://github.com/Kov404/CVE-2024-51358](https://github.com/Kov404/CVE-2024-51358) :  ![starts](https://img.shields.io/github/stars/Kov404/CVE-2024-51358.svg) ![forks](https://img.shields.io/github/forks/Kov404/CVE-2024-51358.svg)


## CVE-2024-37054
 Deserialization of untrusted data can occur in versions of the MLflow platform running version 0.9.0 or newer, enabling a maliciously uploaded PyFunc model to run arbitrary code on an end user’s system when interacted with.

- [https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell](https://github.com/Spydomain/CVE-2024-37054-MLflow-reverse-shell) :  ![starts](https://img.shields.io/github/stars/Spydomain/CVE-2024-37054-MLflow-reverse-shell.svg) ![forks](https://img.shields.io/github/forks/Spydomain/CVE-2024-37054-MLflow-reverse-shell.svg)


## CVE-2024-37032
 Ollama before 0.1.34 does not validate the format of the digest (sha256 with 64 hex digits) when getting the model path, and thus mishandles the TestGetBlobsPath test cases such as fewer than 64 hex digits, more than 64 hex digits, or an initial ../ substring.

- [https://github.com/itzSh4dowxZ/CVE-2024-37032-PoC](https://github.com/itzSh4dowxZ/CVE-2024-37032-PoC) :  ![starts](https://img.shields.io/github/stars/itzSh4dowxZ/CVE-2024-37032-PoC.svg) ![forks](https://img.shields.io/github/forks/itzSh4dowxZ/CVE-2024-37032-PoC.svg)


## CVE-2024-34070
 Froxlor is open source server administration software. Prior to 2.1.9, a Stored Blind Cross-Site Scripting (XSS) vulnerability was identified in the Failed Login Attempts Logging Feature of the Froxlor Application. An unauthenticated User can inject malicious scripts in the loginname parameter on the Login attempt, which will then be executed when viewed by the Administrator in the System Logs.  By exploiting this vulnerability, the attacker can perform various malicious actions such as forcing the Administrator to execute actions without their knowledge or consent. For instance, the attacker can force the Administrator to add a new administrator controlled by the attacker, thereby giving the attacker full control over the application. This vulnerability is fixed in 2.1.9.

- [https://github.com/Akira07210/Exploit-CVE-2024-34070](https://github.com/Akira07210/Exploit-CVE-2024-34070) :  ![starts](https://img.shields.io/github/stars/Akira07210/Exploit-CVE-2024-34070.svg) ![forks](https://img.shields.io/github/forks/Akira07210/Exploit-CVE-2024-34070.svg)


## CVE-2024-32019
 Netdata is an open source observability tool. In affected versions the `ndsudo` tool shipped with affected versions of the Netdata Agent allows an attacker to run arbitrary programs with root permissions. The `ndsudo` tool is packaged as a `root`-owned executable with the SUID bit set. It only runs a restricted set of external commands, but its search paths are supplied by the `PATH` environment variable. This allows an attacker to control where `ndsudo` looks for these commands, which may be a path the attacker has write access to. This may lead to local privilege escalation. This vulnerability has been addressed in versions 1.45.3 and 1.45.2-169. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Akira07210/Exploit-CVE-2024-34070](https://github.com/Akira07210/Exploit-CVE-2024-34070) :  ![starts](https://img.shields.io/github/stars/Akira07210/Exploit-CVE-2024-34070.svg) ![forks](https://img.shields.io/github/forks/Akira07210/Exploit-CVE-2024-34070.svg)


## CVE-2024-27198
 In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible

- [https://github.com/cmpnn-romain/CVE-2024-27198_Lab](https://github.com/cmpnn-romain/CVE-2024-27198_Lab) :  ![starts](https://img.shields.io/github/stars/cmpnn-romain/CVE-2024-27198_Lab.svg) ![forks](https://img.shields.io/github/forks/cmpnn-romain/CVE-2024-27198_Lab.svg)
- [https://github.com/Ne0zer01/CVE-2024-27198_LAB](https://github.com/Ne0zer01/CVE-2024-27198_LAB) :  ![starts](https://img.shields.io/github/stars/Ne0zer01/CVE-2024-27198_LAB.svg) ![forks](https://img.shields.io/github/forks/Ne0zer01/CVE-2024-27198_LAB.svg)


## CVE-2023-34468
You are recommended to upgrade to version 1.22.0 or later which fixes this issue.

- [https://github.com/sbouabid-sec/CVE-2023-34468-POC](https://github.com/sbouabid-sec/CVE-2023-34468-POC) :  ![starts](https://img.shields.io/github/stars/sbouabid-sec/CVE-2023-34468-POC.svg) ![forks](https://img.shields.io/github/forks/sbouabid-sec/CVE-2023-34468-POC.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe](https://github.com/osungjinwoo/CVE-2022-0847-Dirty-Pipe) :  ![starts](https://img.shields.io/github/stars/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg) ![forks](https://img.shields.io/github/forks/osungjinwoo/CVE-2022-0847-Dirty-Pipe.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/usman-khan-23626/-CVE-2021-4034](https://github.com/usman-khan-23626/-CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/usman-khan-23626/-CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/usman-khan-23626/-CVE-2021-4034.svg)

