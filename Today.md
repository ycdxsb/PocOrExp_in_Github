# Update 2024-08-29
## CVE-2024-38856
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/emanueldosreis/CVE-2024-38856](https://github.com/emanueldosreis/CVE-2024-38856) :  ![starts](https://img.shields.io/github/stars/emanueldosreis/CVE-2024-38856.svg) ![forks](https://img.shields.io/github/forks/emanueldosreis/CVE-2024-38856.svg)


## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/patchpoint/CVE-2024-38063](https://github.com/patchpoint/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/patchpoint/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/patchpoint/CVE-2024-38063.svg)


## CVE-2024-36401
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/justin-p/geoexplorer](https://github.com/justin-p/geoexplorer) :  ![starts](https://img.shields.io/github/stars/justin-p/geoexplorer.svg) ![forks](https://img.shields.io/github/forks/justin-p/geoexplorer.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/JJoosh/CVE-2024-32002](https://github.com/JJoosh/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/JJoosh/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/JJoosh/CVE-2024-32002.svg)
- [https://github.com/JJoosh/malicious-hook](https://github.com/JJoosh/malicious-hook) :  ![starts](https://img.shields.io/github/stars/JJoosh/malicious-hook.svg) ![forks](https://img.shields.io/github/forks/JJoosh/malicious-hook.svg)


## CVE-2024-28085
 wall in util-linux through 2.40, often installed with setgid tty permissions, allows escape sequences to be sent to other users' terminals through argv. (Specifically, escape sequences received from stdin are blocked, but escape sequences received from argv are not blocked.) There may be plausible scenarios where this leads to account takeover.

- [https://github.com/oditynet/sleepall](https://github.com/oditynet/sleepall) :  ![starts](https://img.shields.io/github/stars/oditynet/sleepall.svg) ![forks](https://img.shields.io/github/forks/oditynet/sleepall.svg)


## CVE-2024-28000
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/arch1m3d/CVE-2024-28000](https://github.com/arch1m3d/CVE-2024-28000) :  ![starts](https://img.shields.io/github/stars/arch1m3d/CVE-2024-28000.svg) ![forks](https://img.shields.io/github/forks/arch1m3d/CVE-2024-28000.svg)


## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the &quot;Package Import&quot; feature, allows authenticated users having the &quot;Import Templates&quot; permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26](https://github.com/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26) :  ![starts](https://img.shields.io/github/stars/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26.svg) ![forks](https://img.shields.io/github/forks/thisisveryfunny/CVE-2024-25641-RCE-Automated-Exploit-Cacti-1.2.26.svg)
- [https://github.com/Safarchand/CVE-2024-25641](https://github.com/Safarchand/CVE-2024-25641) :  ![starts](https://img.shields.io/github/stars/Safarchand/CVE-2024-25641.svg) ![forks](https://img.shields.io/github/forks/Safarchand/CVE-2024-25641.svg)


## CVE-2024-5932
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/niktoproject/CVE-2024-5932](https://github.com/niktoproject/CVE-2024-5932) :  ![starts](https://img.shields.io/github/stars/niktoproject/CVE-2024-5932.svg) ![forks](https://img.shields.io/github/forks/niktoproject/CVE-2024-5932.svg)
- [https://github.com/sqlmap-projects/CVE-2024-5932](https://github.com/sqlmap-projects/CVE-2024-5932) :  ![starts](https://img.shields.io/github/stars/sqlmap-projects/CVE-2024-5932.svg) ![forks](https://img.shields.io/github/forks/sqlmap-projects/CVE-2024-5932.svg)


## CVE-2024-4879
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/fa-rrel/CVE-2024-4879](https://github.com/fa-rrel/CVE-2024-4879) :  ![starts](https://img.shields.io/github/stars/fa-rrel/CVE-2024-4879.svg) ![forks](https://img.shields.io/github/forks/fa-rrel/CVE-2024-4879.svg)


## CVE-2024-4299
 The system configuration interface of HGiga iSherlock (including MailSherlock, SpamSherock, AuditSherlock) fails to filter special characters in certain function parameters, allowing remote attackers with administrative privileges to exploit this vulnerability for Command Injection attacks, enabling execution of arbitrary system commands.

- [https://github.com/thanhh23/CVE-2024-42992](https://github.com/thanhh23/CVE-2024-42992) :  ![starts](https://img.shields.io/github/stars/thanhh23/CVE-2024-42992.svg) ![forks](https://img.shields.io/github/forks/thanhh23/CVE-2024-42992.svg)


## CVE-2023-41425
 Cross Site Scripting vulnerability in Wonder CMS v.3.2.0 thru v.3.4.2 allows a remote attacker to execute arbitrary code via a crafted script uploaded to the installModule component.

- [https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE](https://github.com/thefizzyfish/CVE-2023-41425-wonderCMS_RCE) :  ![starts](https://img.shields.io/github/stars/thefizzyfish/CVE-2023-41425-wonderCMS_RCE.svg) ![forks](https://img.shields.io/github/forks/thefizzyfish/CVE-2023-41425-wonderCMS_RCE.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/qrxnz/CVE-2023-4220](https://github.com/qrxnz/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/qrxnz/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/qrxnz/CVE-2023-4220.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE](https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE) :  ![starts](https://img.shields.io/github/stars/Zyx2440/Apache-HTTP-Server-2.4.50-RCE.svg) ![forks](https://img.shields.io/github/forks/Zyx2440/Apache-HTTP-Server-2.4.50-RCE.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE](https://github.com/Zyx2440/Apache-HTTP-Server-2.4.50-RCE) :  ![starts](https://img.shields.io/github/stars/Zyx2440/Apache-HTTP-Server-2.4.50-RCE.svg) ![forks](https://img.shields.io/github/forks/Zyx2440/Apache-HTTP-Server-2.4.50-RCE.svg)


## CVE-2016-20012
 ** DISPUTED ** OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product.

- [https://github.com/aztec-eagle/cve-2016-20012](https://github.com/aztec-eagle/cve-2016-20012) :  ![starts](https://img.shields.io/github/stars/aztec-eagle/cve-2016-20012.svg) ![forks](https://img.shields.io/github/forks/aztec-eagle/cve-2016-20012.svg)

