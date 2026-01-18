# Update 2026-01-18
## CVE-2026-22812
 OpenCode is an open source AI coding agent. Prior to 1.0.216, OpenCode automatically starts an unauthenticated HTTP server that allows any local process (or any website via permissive CORS) to execute arbitrary shell commands with the user's privileges. This vulnerability is fixed in 1.0.216.

- [https://github.com/rohmatariow/CVE-2026-22812-exploit](https://github.com/rohmatariow/CVE-2026-22812-exploit) :  ![starts](https://img.shields.io/github/stars/rohmatariow/CVE-2026-22812-exploit.svg) ![forks](https://img.shields.io/github/forks/rohmatariow/CVE-2026-22812-exploit.svg)
- [https://github.com/Udyz/CVE-2026-22812-Exp](https://github.com/Udyz/CVE-2026-22812-Exp) :  ![starts](https://img.shields.io/github/stars/Udyz/CVE-2026-22812-Exp.svg) ![forks](https://img.shields.io/github/forks/Udyz/CVE-2026-22812-Exp.svg)


## CVE-2025-69581
 An issue was discovered in Chamillo LMS 1.11.2. The Social Network /personal_data endpoint exposes full sensitive user information even after logout because proper cache-control is missing. Using the browser back button restores all personal data, allowing unauthorized users on the same device to view confidential information. This leads to profiling, impersonation, targeted attacks, and significant privacy risks.

- [https://github.com/Rivek619/CVE-2025-69581](https://github.com/Rivek619/CVE-2025-69581) :  ![starts](https://img.shields.io/github/stars/Rivek619/CVE-2025-69581.svg) ![forks](https://img.shields.io/github/forks/Rivek619/CVE-2025-69581.svg)


## CVE-2025-68921
 SteelSeries Nahimic 3 1.10.7 allows Directory traversal.

- [https://github.com/ZeroMemoryEx/CVE-2025-68921](https://github.com/ZeroMemoryEx/CVE-2025-68921) :  ![starts](https://img.shields.io/github/stars/ZeroMemoryEx/CVE-2025-68921.svg) ![forks](https://img.shields.io/github/forks/ZeroMemoryEx/CVE-2025-68921.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)


## CVE-2025-61686
 React Router is a router for React. In @react-router/node versions 7.0.0 through 7.9.3, @remix-run/deno prior to version 2.17.2, and @remix-run/node prior to version 2.17.2, if createFileSessionStorage() is being used from @react-router/node (or @remix-run/node/@remix-run/deno in Remix v2) with an unsigned cookie, it is possible for an attacker to cause the session to try to read/write from a location outside the specified session file directory. The success of the attack would depend on the permissions of the web server process to access those files. Read files cannot be returned directly to the attacker. Session file reads would only succeed if the file matched the expected session file format. If the file matched the session file format, the data would be populated into the server side session but not directly returned to the attacker unless the application logic returned specific session information. This issue has been patched in @react-router/node version 7.9.4, @remix-run/deno version 2.17.2, and @remix-run/node version 2.17.2.

- [https://github.com/Kai-One001/React-Router-CVE-2025-61686-](https://github.com/Kai-One001/React-Router-CVE-2025-61686-) :  ![starts](https://img.shields.io/github/stars/Kai-One001/React-Router-CVE-2025-61686-.svg) ![forks](https://img.shields.io/github/forks/Kai-One001/React-Router-CVE-2025-61686-.svg)


## CVE-2025-59287
 Deserialization of untrusted data in Windows Server Update Service allows an unauthorized attacker to execute code over a network.

- [https://github.com/you-dream-1hall/CVE-2025-59287](https://github.com/you-dream-1hall/CVE-2025-59287) :  ![starts](https://img.shields.io/github/stars/you-dream-1hall/CVE-2025-59287.svg) ![forks](https://img.shields.io/github/forks/you-dream-1hall/CVE-2025-59287.svg)
- [https://github.com/LuemmelSec/CVE-2025-59287---WSUS-SCCM-RCE](https://github.com/LuemmelSec/CVE-2025-59287---WSUS-SCCM-RCE) :  ![starts](https://img.shields.io/github/stars/LuemmelSec/CVE-2025-59287---WSUS-SCCM-RCE.svg) ![forks](https://img.shields.io/github/forks/LuemmelSec/CVE-2025-59287---WSUS-SCCM-RCE.svg)


## CVE-2025-53770
Microsoft is preparing and fully testing a comprehensive update to address this vulnerability.  In the meantime, please make sure that the mitigation provided in this CVE documentation is in place so that you are protected from exploitation.

- [https://github.com/anwakub/CVE-2025-53770](https://github.com/anwakub/CVE-2025-53770) :  ![starts](https://img.shields.io/github/stars/anwakub/CVE-2025-53770.svg) ![forks](https://img.shields.io/github/forks/anwakub/CVE-2025-53770.svg)


## CVE-2025-20393
This vulnerability is due to insufficient validation of HTTP requests by the Spam Quarantine feature. An attacker could exploit this vulnerability by sending a crafted HTTP request to the affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying operating system with&nbsp;root privileges.

- [https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Cisco-AsyncOS-CVE-2025-20393-Scanner](https://github.com/cyberdudebivash/CYBERDUDEBIVASH-Cisco-AsyncOS-CVE-2025-20393-Scanner) :  ![starts](https://img.shields.io/github/stars/cyberdudebivash/CYBERDUDEBIVASH-Cisco-AsyncOS-CVE-2025-20393-Scanner.svg) ![forks](https://img.shields.io/github/forks/cyberdudebivash/CYBERDUDEBIVASH-Cisco-AsyncOS-CVE-2025-20393-Scanner.svg)


## CVE-2025-9933
 A vulnerability has been found in PHPGurukul Beauty Parlour Management System 1.1. Affected by this issue is some unknown functionality of the file /admin/view-appointment.php. Such manipulation of the argument viewid leads to sql injection. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/titanmaster96/cve-2025-9933](https://github.com/titanmaster96/cve-2025-9933) :  ![starts](https://img.shields.io/github/stars/titanmaster96/cve-2025-9933.svg) ![forks](https://img.shields.io/github/forks/titanmaster96/cve-2025-9933.svg)


## CVE-2024-50050
 Llama Stack prior to revision 7a8aa775e5a267cf8660d83140011a0b7f91e005 used pickle as a serialization format for socket communication, potentially allowing for remote code execution. Socket communication has been changed to use JSON instead.

- [https://github.com/sastraadiwiguna-purpleeliteteaming/LlamaStack-RCE-Deterministic-Supply-Chain-Exploitation-Hardening-Framework-CVE-2024-50050-](https://github.com/sastraadiwiguna-purpleeliteteaming/LlamaStack-RCE-Deterministic-Supply-Chain-Exploitation-Hardening-Framework-CVE-2024-50050-) :  ![starts](https://img.shields.io/github/stars/sastraadiwiguna-purpleeliteteaming/LlamaStack-RCE-Deterministic-Supply-Chain-Exploitation-Hardening-Framework-CVE-2024-50050-.svg) ![forks](https://img.shields.io/github/forks/sastraadiwiguna-purpleeliteteaming/LlamaStack-RCE-Deterministic-Supply-Chain-Exploitation-Hardening-Framework-CVE-2024-50050-.svg)


## CVE-2024-46982
 Next.js is a React framework for building full-stack web applications. By sending a crafted HTTP request, it is possible to poison the cache of a non-dynamic server-side rendered route in the pages router (this does not affect the app router). When this crafted request is sent it could coerce Next.js to cache a route that is meant to not be cached and send a `Cache-Control: s-maxage=1, stale-while-revalidate` header which some upstream CDNs may cache as well. To be potentially affected all of the following must apply: 1. Next.js between 13.5.1 and 14.2.9, 2. Using pages router, & 3. Using non-dynamic server-side rendered routes e.g. `pages/dashboard.tsx` not `pages/blog/[slug].tsx`. This vulnerability was resolved in Next.js v13.5.7, v14.2.10, and later. We recommend upgrading regardless of whether you can reproduce the issue or not. There are no official or recommended workarounds for this issue, we recommend that users patch to a safe version.

- [https://github.com/samuel871211/CVE-2024-46982-Reproduction](https://github.com/samuel871211/CVE-2024-46982-Reproduction) :  ![starts](https://img.shields.io/github/stars/samuel871211/CVE-2024-46982-Reproduction.svg) ![forks](https://img.shields.io/github/forks/samuel871211/CVE-2024-46982-Reproduction.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/honypot/CVE-2021-41773](https://github.com/honypot/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/honypot/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/honypot/CVE-2021-41773.svg)


## CVE-2019-9053
 An issue was discovered in CMS Made Simple 2.2.8. It is possible with the News module, through a crafted URL, to achieve unauthenticated blind time-based SQL injection via the m1_idlist parameter.

- [https://github.com/tim-karov/cmsms-sqli](https://github.com/tim-karov/cmsms-sqli) :  ![starts](https://img.shields.io/github/stars/tim-karov/cmsms-sqli.svg) ![forks](https://img.shields.io/github/forks/tim-karov/cmsms-sqli.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka "ShellShock."  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/NamiKaze02/Shellshock](https://github.com/NamiKaze02/Shellshock) :  ![starts](https://img.shields.io/github/stars/NamiKaze02/Shellshock.svg) ![forks](https://img.shields.io/github/forks/NamiKaze02/Shellshock.svg)


## CVE-2013-3900
Exploitation of this vulnerability requires that a user or application run or install a specially crafted, signed PE file. An attacker could modify an... See more at https://msrc.microsoft.com/update-guide/vulnerability/CVE-2013-3900

- [https://github.com/ksgassama-lab/vulnerability-remediation-cve-2013-3900](https://github.com/ksgassama-lab/vulnerability-remediation-cve-2013-3900) :  ![starts](https://img.shields.io/github/stars/ksgassama-lab/vulnerability-remediation-cve-2013-3900.svg) ![forks](https://img.shields.io/github/forks/ksgassama-lab/vulnerability-remediation-cve-2013-3900.svg)

