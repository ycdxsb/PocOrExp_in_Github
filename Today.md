# Update 2024-06-03
## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/tobelight/cve_2024_32002](https://github.com/tobelight/cve_2024_32002) :  ![starts](https://img.shields.io/github/stars/tobelight/cve_2024_32002.svg) ![forks](https://img.shields.io/github/forks/tobelight/cve_2024_32002.svg)
- [https://github.com/tobelight/cve_2024_32002_hook](https://github.com/tobelight/cve_2024_32002_hook) :  ![starts](https://img.shields.io/github/stars/tobelight/cve_2024_32002_hook.svg) ![forks](https://img.shields.io/github/forks/tobelight/cve_2024_32002_hook.svg)
- [https://github.com/coffeescholar/ReplaceAllGit](https://github.com/coffeescholar/ReplaceAllGit) :  ![starts](https://img.shields.io/github/stars/coffeescholar/ReplaceAllGit.svg) ![forks](https://img.shields.io/github/forks/coffeescholar/ReplaceAllGit.svg)


## CVE-2024-24919
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/ifconfig-me/CVE-2024-24919-Bulk-Scanner](https://github.com/ifconfig-me/CVE-2024-24919-Bulk-Scanner) :  ![starts](https://img.shields.io/github/stars/ifconfig-me/CVE-2024-24919-Bulk-Scanner.svg) ![forks](https://img.shields.io/github/forks/ifconfig-me/CVE-2024-24919-Bulk-Scanner.svg)
- [https://github.com/r4p3c4/CVE-2024-24919-Checkpoint-Firewall-VPN-Check](https://github.com/r4p3c4/CVE-2024-24919-Checkpoint-Firewall-VPN-Check) :  ![starts](https://img.shields.io/github/stars/r4p3c4/CVE-2024-24919-Checkpoint-Firewall-VPN-Check.svg) ![forks](https://img.shields.io/github/forks/r4p3c4/CVE-2024-24919-Checkpoint-Firewall-VPN-Check.svg)
- [https://github.com/r4p3c4/CVE-2024-24919-Exploit-PoC-Checkpoint-Firewall-VPN](https://github.com/r4p3c4/CVE-2024-24919-Exploit-PoC-Checkpoint-Firewall-VPN) :  ![starts](https://img.shields.io/github/stars/r4p3c4/CVE-2024-24919-Exploit-PoC-Checkpoint-Firewall-VPN.svg) ![forks](https://img.shields.io/github/forks/r4p3c4/CVE-2024-24919-Exploit-PoC-Checkpoint-Firewall-VPN.svg)
- [https://github.com/YN1337/CVE-2024-24919](https://github.com/YN1337/CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/YN1337/CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/YN1337/CVE-2024-24919.svg)


## CVE-2023-36085
 The sisqualWFM 7.1.319.103 thru 7.1.319.111 for Android, has a host header injection vulnerability in its &quot;/sisqualIdentityServer/core/&quot; endpoint. By modifying the HTTP Host header, an attacker can change webpage links and even redirect users to arbitrary or malicious locations. This can lead to phishing attacks, malware distribution, and unauthorized access to sensitive resources.

- [https://github.com/omershaik0/CVE-2023-36085_SISQUALWFM-Host-Header-Injection](https://github.com/omershaik0/CVE-2023-36085_SISQUALWFM-Host-Header-Injection) :  ![starts](https://img.shields.io/github/stars/omershaik0/CVE-2023-36085_SISQUALWFM-Host-Header-Injection.svg) ![forks](https://img.shields.io/github/forks/omershaik0/CVE-2023-36085_SISQUALWFM-Host-Header-Injection.svg)


## CVE-2020-9484
 When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to 7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is configured with sessionAttributeValueClassNameFilter=&quot;null&quot; (the default unless a SecurityManager is used) or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker knows the relative file path from the storage location used by FileStore to the file the attacker has control over; then, using a specifically crafted request, the attacker will be able to trigger remote code execution via deserialization of the file under their control. Note that all of conditions a) to d) must be true for the attack to succeed.

- [https://github.com/pxcs/webLogin-DEV](https://github.com/pxcs/webLogin-DEV) :  ![starts](https://img.shields.io/github/stars/pxcs/webLogin-DEV.svg) ![forks](https://img.shields.io/github/forks/pxcs/webLogin-DEV.svg)


## CVE-2019-12616
 An issue was discovered in phpMyAdmin before 4.9.0. A vulnerability was found that allows an attacker to trigger a CSRF attack against a phpMyAdmin user. The attacker can trick the user, for instance through a broken &lt;img&gt; tag pointing at the victim's phpMyAdmin database, and the attacker can potentially deliver a payload (such as a specific INSERT or DELETE statement) to the victim.

- [https://github.com/Cappricio-Securities/CVE-2019-12616](https://github.com/Cappricio-Securities/CVE-2019-12616) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2019-12616.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2019-12616.svg)

