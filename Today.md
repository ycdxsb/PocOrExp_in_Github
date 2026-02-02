# Update 2026-02-02
## CVE-2026-25211
 Llama Stack (aka llama-stack) before 0.4.0rc3 does not censor the pgvector password in the initialization log.

- [https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211](https://github.com/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211) :  ![starts](https://img.shields.io/github/stars/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/Llama-Stack-0.4.0rc3-local-CVE-2026-25211.svg)


## CVE-2026-25126
 PolarLearn is a free and open-source learning program. Prior to version 0-PRERELEASE-15, the vote API route (`POST /api/v1/forum/vote`) trusts the JSON body’s `direction` value without runtime validation. TypeScript types are not enforced at runtime, so an attacker can send arbitrary strings (e.g., `"x"`) as `direction`. Downstream (`VoteServer`) treats any non-`"up"` and non-`null` value as a downvote and persists the invalid value in `votes_data`. This can be exploited to bypass intended business logic. Version 0-PRERELEASE-15 fixes the vulnerability.

- [https://github.com/Jvr2022/CVE-2026-25126](https://github.com/Jvr2022/CVE-2026-25126) :  ![starts](https://img.shields.io/github/stars/Jvr2022/CVE-2026-25126.svg) ![forks](https://img.shields.io/github/forks/Jvr2022/CVE-2026-25126.svg)


## CVE-2026-25047
 deepHas provides a test for the existence of a nested object key and optionally returns that key. A prototype pollution vulnerability exists in version 1.0.7 of the deephas npm package that allows an attacker to modify global object behavior. This issue was fixed in version 1.0.8.

- [https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-](https://github.com/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-) :  ![starts](https://img.shields.io/github/stars/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/deephas-1.0.7-Prototype-Pollution-PoC-CVE-2026-25047-.svg)


## CVE-2026-24858
 An Authentication Bypass Using an Alternate Path or Channel vulnerability [CWE-288] vulnerability in Fortinet FortiAnalyzer 7.6.0 through 7.6.5, FortiAnalyzer 7.4.0 through 7.4.9, FortiAnalyzer 7.2.0 through 7.2.11, FortiAnalyzer 7.0.0 through 7.0.15, FortiManager 7.6.0 through 7.6.5, FortiManager 7.4.0 through 7.4.9, FortiManager 7.2.0 through 7.2.11, FortiManager 7.0.0 through 7.0.15, FortiOS 7.6.0 through 7.6.5, FortiOS 7.4.0 through 7.4.10, FortiOS 7.2.0 through 7.2.12, FortiOS 7.0.0 through 7.0.18, FortiProxy 7.6.0 through 7.6.4, FortiProxy 7.4.0 through 7.4.12, FortiProxy 7.2.0 through 7.2.15, FortiProxy 7.0.0 through 7.0.22, FortiWeb 8.0.0 through 8.0.3, FortiWeb 7.6.0 through 7.6.6, FortiWeb 7.4.0 through 7.4.11 may allow an attacker with a FortiCloud account and a registered device to log into other devices registered to other accounts, if FortiCloud SSO authentication is enabled on those devices.

- [https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0004-FortiCloud-SSO-Identity-Singularity.svg)


## CVE-2026-24841
 Dokploy is a free, self-hostable Platform as a Service (PaaS). In versions prior to 0.26.6, a critical command injection vulnerability exists in Dokploy's WebSocket endpoint `/docker-container-terminal`. The `containerId` and `activeWay` parameters are directly interpolated into shell commands without sanitization, allowing authenticated attackers to execute arbitrary commands on the host server. Version 0.26.6 fixes the issue.

- [https://github.com/otakuliu/CVE-2026-24841_Range](https://github.com/otakuliu/CVE-2026-24841_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-24841_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-24841_Range.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/buzz075/CVE-2026-24061](https://github.com/buzz075/CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/buzz075/CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/buzz075/CVE-2026-24061.svg)
- [https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061](https://github.com/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061) :  ![starts](https://img.shields.io/github/stars/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg) ![forks](https://img.shields.io/github/forks/0xXyc/telnet-inetutils-auth-bypass-CVE-2026-24061.svg)


## CVE-2026-22807
 vLLM is an inference and serving engine for large language models (LLMs). Starting in version 0.10.1 and prior to version 0.14.0, vLLM loads Hugging Face `auto_map` dynamic modules during model resolution without gating on `trust_remote_code`, allowing attacker-controlled Python code in a model repo/path to execute at server startup. An attacker who can influence the model repo/path (local directory or remote Hugging Face repo) can achieve arbitrary code execution on the vLLM host during model load. This happens before any request handling and does not require API access. Version 0.14.0 fixes the issue.

- [https://github.com/otakuliu/CVE-2026-22807_Range](https://github.com/otakuliu/CVE-2026-22807_Range) :  ![starts](https://img.shields.io/github/stars/otakuliu/CVE-2026-22807_Range.svg) ![forks](https://img.shields.io/github/forks/otakuliu/CVE-2026-22807_Range.svg)


## CVE-2026-21509
 Reliance on untrusted inputs in a security decision in Microsoft Office allows an unauthorized attacker to bypass a security feature locally.

- [https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE](https://github.com/SimoesCTT/CTT-NFS-Vortex-RCE) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/CTT-NFS-Vortex-RCE.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/CTT-NFS-Vortex-RCE.svg)
- [https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-](https://github.com/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0007-The-OLE-Vortex-Laminar-Bypass-.svg)


## CVE-2026-20871
 Use after free in Desktop Windows Manager allows an authorized attacker to elevate privileges locally.

- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)
- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)


## CVE-2026-20805
 Exposure of sensitive information to an unauthorized actor in Desktop Windows Manager allows an authorized attacker to disclose information locally.

- [https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/-SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)
- [https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity](https://github.com/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity) :  ![starts](https://img.shields.io/github/stars/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg) ![forks](https://img.shields.io/github/forks/SimoesCTT/SCTT-2026-33-0002-DWM-Visual-Field-Singularity.svg)


## CVE-2026-0628
 Insufficient policy enforcement in WebView tag in Google Chrome prior to 143.0.7499.192 allowed an attacker who convinced a user to install a malicious extension to inject scripts or HTML into a privileged page via a crafted Chrome Extension. (Chromium security severity: High)

- [https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation](https://github.com/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/Dissecting-CVE-2026-0628-Chromium-Extension-Privilege-Escalation.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-canary-14x.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-pnp.svg)


## CVE-2025-61505
 e107 CMS thru 2.3.3 are vulnerable to insecure deserialization in the `install.php` script. The script processes user-controlled input in the `previous_steps` POST parameter using `unserialize(base64_decode())` without validation, allowing attackers to craft malicious serialized data. This could lead to remote code execution, arbitrary file operations, or denial of service, depending on available PHP object gadgets in the codebase.

- [https://github.com/pescada-dev/CVE-2025-61505](https://github.com/pescada-dev/CVE-2025-61505) :  ![starts](https://img.shields.io/github/stars/pescada-dev/CVE-2025-61505.svg) ![forks](https://img.shields.io/github/forks/pescada-dev/CVE-2025-61505.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/AdityaBhatt3010/React2Shell-CVE-2025-55182](https://github.com/AdityaBhatt3010/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/AdityaBhatt3010/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/AdityaBhatt3010/React2Shell-CVE-2025-55182.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/DayDayDayDreaming/backup-exec-cve-48384](https://github.com/DayDayDayDreaming/backup-exec-cve-48384) :  ![starts](https://img.shields.io/github/stars/DayDayDayDreaming/backup-exec-cve-48384.svg) ![forks](https://img.shields.io/github/forks/DayDayDayDreaming/backup-exec-cve-48384.svg)


## CVE-2025-40554
 SolarWinds Web Help Desk was found to be susceptible to an authentication bypass vulnerability that, if exploited, could allow an attacker to invoke specific actions within Web Help Desk.

- [https://github.com/Skynoxk/CVE-2025-40554](https://github.com/Skynoxk/CVE-2025-40554) :  ![starts](https://img.shields.io/github/stars/Skynoxk/CVE-2025-40554.svg) ![forks](https://img.shields.io/github/forks/Skynoxk/CVE-2025-40554.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)


## CVE-2025-6150
 A vulnerability classified as critical was found in TOTOLINK X15 1.0.0-B20230714.1105. Affected by this vulnerability is an unknown functionality of the file /boafrm/formMultiAP of the component HTTP POST Request Handler. The manipulation of the argument submit-url leads to buffer overflow. The attack can be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/pescada-dev/CVE-2025-61506](https://github.com/pescada-dev/CVE-2025-61506) :  ![starts](https://img.shields.io/github/stars/pescada-dev/CVE-2025-61506.svg) ![forks](https://img.shields.io/github/forks/pescada-dev/CVE-2025-61506.svg)


## CVE-2025-2304
When a user wishes to change his password, the 'updated_ajax' method of the UsersController is called. The vulnerability stems from the use of the dangerous permit! method, which allows all parameters to pass through without any filtering.

- [https://github.com/whiteov3rflow/CVE-2025-2304-POC](https://github.com/whiteov3rflow/CVE-2025-2304-POC) :  ![starts](https://img.shields.io/github/stars/whiteov3rflow/CVE-2025-2304-POC.svg) ![forks](https://img.shields.io/github/forks/whiteov3rflow/CVE-2025-2304-POC.svg)
- [https://github.com/innocentx0/CVE-2025-2304-POC](https://github.com/innocentx0/CVE-2025-2304-POC) :  ![starts](https://img.shields.io/github/stars/innocentx0/CVE-2025-2304-POC.svg) ![forks](https://img.shields.io/github/forks/innocentx0/CVE-2025-2304-POC.svg)
- [https://github.com/d3vn0mi/cve-2025-2304-poc](https://github.com/d3vn0mi/cve-2025-2304-poc) :  ![starts](https://img.shields.io/github/stars/d3vn0mi/cve-2025-2304-poc.svg) ![forks](https://img.shields.io/github/forks/d3vn0mi/cve-2025-2304-poc.svg)


## CVE-2024-46987
 Camaleon CMS is a dynamic and advanced content management system based on Ruby on Rails. A path traversal vulnerability accessible via MediaController's download_private_file method allows authenticated users to download any file on the web server Camaleon CMS is running on (depending on the file permissions). This issue may lead to Information Disclosure. This issue has been addressed in release version 2.8.2. Users are advised to upgrade. There are no known workarounds for this vulnerability.

- [https://github.com/Goultarde/CVE-2024-46987](https://github.com/Goultarde/CVE-2024-46987) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2024-46987.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2024-46987.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/DayDayDayDreaming/backup-exec-hook](https://github.com/DayDayDayDreaming/backup-exec-hook) :  ![starts](https://img.shields.io/github/stars/DayDayDayDreaming/backup-exec-hook.svg) ![forks](https://img.shields.io/github/forks/DayDayDayDreaming/backup-exec-hook.svg)
- [https://github.com/DayDayDayDreaming/backup-exec-cve-32002](https://github.com/DayDayDayDreaming/backup-exec-cve-32002) :  ![starts](https://img.shields.io/github/stars/DayDayDayDreaming/backup-exec-cve-32002.svg) ![forks](https://img.shields.io/github/forks/DayDayDayDreaming/backup-exec-cve-32002.svg)


## CVE-2024-27397
asynchronously from a workqueue.

- [https://github.com/hackingyseguridad/root](https://github.com/hackingyseguridad/root) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/root.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/root.svg)


## CVE-2023-23397
 Microsoft Outlook Elevation of Privilege Vulnerability

- [https://github.com/medyassineakhmari/CVE_2023_23397](https://github.com/medyassineakhmari/CVE_2023_23397) :  ![starts](https://img.shields.io/github/stars/medyassineakhmari/CVE_2023_23397.svg) ![forks](https://img.shields.io/github/forks/medyassineakhmari/CVE_2023_23397.svg)


## CVE-2022-0847
 A flaw was found in the way the "flags" member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/bluedragonsecurity/Linux-Kernel-Dirty-Pipe-Exploitation-Logic-Bug-](https://github.com/bluedragonsecurity/Linux-Kernel-Dirty-Pipe-Exploitation-Logic-Bug-) :  ![starts](https://img.shields.io/github/stars/bluedragonsecurity/Linux-Kernel-Dirty-Pipe-Exploitation-Logic-Bug-.svg) ![forks](https://img.shields.io/github/forks/bluedragonsecurity/Linux-Kernel-Dirty-Pipe-Exploitation-Logic-Bug-.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)

