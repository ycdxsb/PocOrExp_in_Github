# Update 2026-02-19
## CVE-2026-25991
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, there is a Blind Server-Side Request Forgery (SSRF) vulnerability in the Cookmate recipe import feature of Tandoor Recipes. The application fails to validate the destination URL after following HTTP redirects, allowing any authenticated user (including standard users without administrative privileges) to force the server to connect to arbitrary internal or external resources. The vulnerability lies in cookbook/integration/cookmate.py, within the Cookmate integration class. This vulnerability can be leveraged to scan internal network ports, access cloud instance metadata (e.g., AWS/GCP Metadata Service), or disclose the server's real IP address. This vulnerability is fixed in 2.5.1.

- [https://github.com/drkim-dev/CVE-2026-25991](https://github.com/drkim-dev/CVE-2026-25991) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25991.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25991.svg)


## CVE-2026-25964
 Tandoor Recipes is an application for managing recipes, planning meals, and building shopping lists. Prior to 2.5.1, a Path Traversal vulnerability in the RecipeImport workflow of Tandoor Recipes allows authenticated users with import permissions to read arbitrary files on the server. This vulnerability stems from a lack of input validation in the file_path parameter and insufficient checks in the Local storage backend, enabling an attacker to bypass storage directory restrictions and access sensitive system files (e.g., /etc/passwd) or application configuration files (e.g., settings.py), potentially leading to full system compromise. This vulnerability is fixed in 2.5.1.

- [https://github.com/drkim-dev/CVE-2026-25964](https://github.com/drkim-dev/CVE-2026-25964) :  ![starts](https://img.shields.io/github/stars/drkim-dev/CVE-2026-25964.svg) ![forks](https://img.shields.io/github/forks/drkim-dev/CVE-2026-25964.svg)


## CVE-2026-24061
 telnetd in GNU Inetutils through 2.7 allows remote authentication bypass via a "-f root" value for the USER environment variable.

- [https://github.com/ilostmypassword/Melissae](https://github.com/ilostmypassword/Melissae) :  ![starts](https://img.shields.io/github/stars/ilostmypassword/Melissae.svg) ![forks](https://img.shields.io/github/forks/ilostmypassword/Melissae.svg)
- [https://github.com/0p5cur/CVE-2026-24061-POC](https://github.com/0p5cur/CVE-2026-24061-POC) :  ![starts](https://img.shields.io/github/stars/0p5cur/CVE-2026-24061-POC.svg) ![forks](https://img.shields.io/github/forks/0p5cur/CVE-2026-24061-POC.svg)


## CVE-2026-20841
 Improper neutralization of special elements used in a command ('command injection') in Windows Notepad App allows an unauthorized attacker to execute code locally.

- [https://github.com/EleniChristopoulou/PoC-CVE-2026-20841](https://github.com/EleniChristopoulou/PoC-CVE-2026-20841) :  ![starts](https://img.shields.io/github/stars/EleniChristopoulou/PoC-CVE-2026-20841.svg) ![forks](https://img.shields.io/github/forks/EleniChristopoulou/PoC-CVE-2026-20841.svg)


## CVE-2025-70830
 A Server-Side Template Injection (SSTI) vulnerability in the Freemarker template engine of Datart v1.0.0-rc.3 allows authenticated attackers to execute arbitrary code via injecting crafted Freemarker template syntax into the SQL script field.

- [https://github.com/xiaoxiaoranxxx/CVE-2025-70830](https://github.com/xiaoxiaoranxxx/CVE-2025-70830) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70830.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70830.svg)


## CVE-2025-70829
 An information exposure vulnerability in Datart v1.0.0-rc.3 allows authenticated attackers to access sensitive data via a custom H2 JDBC connection string.

- [https://github.com/xiaoxiaoranxxx/CVE-2025-70829](https://github.com/xiaoxiaoranxxx/CVE-2025-70829) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70829.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70829.svg)


## CVE-2025-70828
 An issue in Datart v1.0.0-rc.3 allows attackers to execute arbitrary code via the url parameter in the JDBC configuration

- [https://github.com/xiaoxiaoranxxx/CVE-2025-70828](https://github.com/xiaoxiaoranxxx/CVE-2025-70828) :  ![starts](https://img.shields.io/github/stars/xiaoxiaoranxxx/CVE-2025-70828.svg) ![forks](https://img.shields.io/github/forks/xiaoxiaoranxxx/CVE-2025-70828.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-berry.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-npm-git-dep.svg)


## CVE-2025-65753
 An issue in the TLS certification mechanism of Guardian Gryphon v01.06.0006.22 allows attackers to execute commands as root.

- [https://github.com/diegovargasj/CVE-2025-65753](https://github.com/diegovargasj/CVE-2025-65753) :  ![starts](https://img.shields.io/github/stars/diegovargasj/CVE-2025-65753.svg) ![forks](https://img.shields.io/github/forks/diegovargasj/CVE-2025-65753.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/fBUZk2BH/RSC-Detect-CVE-2025-55182](https://github.com/fBUZk2BH/RSC-Detect-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/fBUZk2BH/RSC-Detect-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/fBUZk2BH/RSC-Detect-CVE-2025-55182.svg)
- [https://github.com/timsonner/React2Shell-CVE-2025-55182](https://github.com/timsonner/React2Shell-CVE-2025-55182) :  ![starts](https://img.shields.io/github/stars/timsonner/React2Shell-CVE-2025-55182.svg) ![forks](https://img.shields.io/github/forks/timsonner/React2Shell-CVE-2025-55182.svg)
- [https://github.com/TheStingR/ReactOOPS-WriteUp](https://github.com/TheStingR/ReactOOPS-WriteUp) :  ![starts](https://img.shields.io/github/stars/TheStingR/ReactOOPS-WriteUp.svg) ![forks](https://img.shields.io/github/forks/TheStingR/ReactOOPS-WriteUp.svg)


## CVE-2025-54939
 LiteSpeed QUIC (LSQUIC) Library before 4.3.1 has an lsquic_engine_packet_in memory leak.

- [https://github.com/yohannslm/CVE-2025-54939](https://github.com/yohannslm/CVE-2025-54939) :  ![starts](https://img.shields.io/github/stars/yohannslm/CVE-2025-54939.svg) ![forks](https://img.shields.io/github/forks/yohannslm/CVE-2025-54939.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/0p5cur/CVE-2025-32463-POC](https://github.com/0p5cur/CVE-2025-32463-POC) :  ![starts](https://img.shields.io/github/stars/0p5cur/CVE-2025-32463-POC.svg) ![forks](https://img.shields.io/github/forks/0p5cur/CVE-2025-32463-POC.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/0p5cur/CVE-2025-32462-POC](https://github.com/0p5cur/CVE-2025-32462-POC) :  ![starts](https://img.shields.io/github/stars/0p5cur/CVE-2025-32462-POC.svg) ![forks](https://img.shields.io/github/forks/0p5cur/CVE-2025-32462-POC.svg)


## CVE-2025-6019
 A Local Privilege Escalation (LPE) vulnerability was found in libblockdev. Generally, the "allow_active" setting in Polkit permits a physically present user to take certain actions based on the session type. Due to the way libblockdev interacts with the udisks daemon, an "allow_active" user on a system may be able escalate to full root privileges on the target host. Normally, udisks mounts user-provided filesystem images with security flags like nosuid and nodev to prevent privilege escalation.  However, a local attacker can create a specially crafted XFS image containing a SUID-root shell, then trick udisks into resizing it. This mounts their malicious filesystem with root privileges, allowing them to execute their SUID-root shell and gain complete control of the system.

- [https://github.com/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn](https://github.com/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn.svg)


## CVE-2025-6018
 A Local Privilege Escalation (LPE) vulnerability has been discovered in pam-config within Linux Pluggable Authentication Modules (PAM). This flaw allows an unprivileged local attacker (for example, a user logged in via SSH) to obtain the elevated privileges normally reserved for a physically present, "allow_active" user. The highest risk is that the attacker can then perform all allow_active yes Polkit actions, which are typically restricted to console users, potentially gaining unauthorized control over system configurations, services, or other sensitive operations.

- [https://github.com/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn](https://github.com/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn) :  ![starts](https://img.shields.io/github/stars/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn.svg) ![forks](https://img.shields.io/github/forks/Goultarde/CVE-2025-6018_CVE-2025-6019_autopwn.svg)


## CVE-2024-55271
 A Cross-Site Request Forgery (CSRF) vulnerability has been identified in phpgurukul Gym Management System 1.0. This issue is present in the profile update functionality of the User Panel, specifically the /profile.php endpoint.

- [https://github.com/shoaibalam112/CVE-2024-55271](https://github.com/shoaibalam112/CVE-2024-55271) :  ![starts](https://img.shields.io/github/stars/shoaibalam112/CVE-2024-55271.svg) ![forks](https://img.shields.io/github/forks/shoaibalam112/CVE-2024-55271.svg)


## CVE-2024-55270
 phpgurukul Student Management System 1.0 is vulnerable to SQL Injection in studentms/admin/search.php via the searchdata parameter.

- [https://github.com/shoaibalam112/CVE-2024-55270](https://github.com/shoaibalam112/CVE-2024-55270) :  ![starts](https://img.shields.io/github/stars/shoaibalam112/CVE-2024-55270.svg) ![forks](https://img.shields.io/github/forks/shoaibalam112/CVE-2024-55270.svg)


## CVE-2024-6232
Regular expressions that allowed excessive backtracking during tarfile.TarFile header parsing are vulnerable to ReDoS via specifically-crafted tar archives.

- [https://github.com/bgutowski/CVE-2025-4517-POC-Sudoers](https://github.com/bgutowski/CVE-2025-4517-POC-Sudoers) :  ![starts](https://img.shields.io/github/stars/bgutowski/CVE-2025-4517-POC-Sudoers.svg) ![forks](https://img.shields.io/github/forks/bgutowski/CVE-2025-4517-POC-Sudoers.svg)


## CVE-2023-31059
 Repetier Server through 1.4.10 allows ..%5c directory traversal for reading files that contain credentials, as demonstrated by connectionLost.php.

- [https://github.com/mbanyamer/CVE-2023-31059-Repetier-Server-1.4.10-Unauthenticated-Path-Traversal](https://github.com/mbanyamer/CVE-2023-31059-Repetier-Server-1.4.10-Unauthenticated-Path-Traversal) :  ![starts](https://img.shields.io/github/stars/mbanyamer/CVE-2023-31059-Repetier-Server-1.4.10-Unauthenticated-Path-Traversal.svg) ![forks](https://img.shields.io/github/forks/mbanyamer/CVE-2023-31059-Repetier-Server-1.4.10-Unauthenticated-Path-Traversal.svg)

