# Update 2024-07-10
## CVE-2024-39031
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/toneemarqus/CVE-2024-39031](https://github.com/toneemarqus/CVE-2024-39031) :  ![starts](https://img.shields.io/github/stars/toneemarqus/CVE-2024-39031.svg) ![forks](https://img.shields.io/github/forks/toneemarqus/CVE-2024-39031.svg)


## CVE-2024-34102
 Adobe Commerce versions 2.4.7, 2.4.6-p5, 2.4.5-p7, 2.4.4-p8 and earlier are affected by an Improper Restriction of XML External Entity Reference ('XXE') vulnerability that could result in arbitrary code execution. An attacker could exploit this vulnerability by sending a crafted XML document that references external entities. Exploitation of this issue does not require user interaction.

- [https://github.com/unknownzerobit/poc](https://github.com/unknownzerobit/poc) :  ![starts](https://img.shields.io/github/stars/unknownzerobit/poc.svg) ![forks](https://img.shields.io/github/forks/unknownzerobit/poc.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/EQSTSeminar/git_rce](https://github.com/EQSTSeminar/git_rce) :  ![starts](https://img.shields.io/github/stars/EQSTSeminar/git_rce.svg) ![forks](https://img.shields.io/github/forks/EQSTSeminar/git_rce.svg)


## CVE-2024-26144
 Rails is a web-application framework. Starting with version 5.2.0, there is a possible sensitive session information leak in Active Storage. By default, Active Storage sends a Set-Cookie header along with the user's session cookie when serving blobs. It also sets Cache-Control to public. Certain proxies may cache the Set-Cookie, leading to an information leak. The vulnerability is fixed in 7.0.8.1 and 6.1.7.7.

- [https://github.com/gmo-ierae/CVE-2024-26144-test](https://github.com/gmo-ierae/CVE-2024-26144-test) :  ![starts](https://img.shields.io/github/stars/gmo-ierae/CVE-2024-26144-test.svg) ![forks](https://img.shields.io/github/forks/gmo-ierae/CVE-2024-26144-test.svg)


## CVE-2024-5009
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sinsinology/CVE-2024-5009](https://github.com/sinsinology/CVE-2024-5009) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-5009.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-5009.svg)


## CVE-2024-4885
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sinsinology/CVE-2024-4885](https://github.com/sinsinology/CVE-2024-4885) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-4885.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-4885.svg)


## CVE-2024-4883
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/sinsinology/CVE-2024-4883](https://github.com/sinsinology/CVE-2024-4883) :  ![starts](https://img.shields.io/github/stars/sinsinology/CVE-2024-4883.svg) ![forks](https://img.shields.io/github/forks/sinsinology/CVE-2024-4883.svg)


## CVE-2024-3094
 Malicious code was discovered in the upstream tarballs of xz, starting with version 5.6.0. Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/yq93dskimzm2/CVE-2024-3094](https://github.com/yq93dskimzm2/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/yq93dskimzm2/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/yq93dskimzm2/CVE-2024-3094.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/Ziad-Sakr/Chamilo-LMS-CVE-2023-4220-Exploit](https://github.com/Ziad-Sakr/Chamilo-LMS-CVE-2023-4220-Exploit) :  ![starts](https://img.shields.io/github/stars/Ziad-Sakr/Chamilo-LMS-CVE-2023-4220-Exploit.svg) ![forks](https://img.shields.io/github/forks/Ziad-Sakr/Chamilo-LMS-CVE-2023-4220-Exploit.svg)


## CVE-2022-48429
 In JetBrains Hub before 2022.3.15573, 2022.2.15572, 2022.1.15583 reflected XSS in dashboards was possible

- [https://github.com/echo-devim/CVE-2022-48429_poc](https://github.com/echo-devim/CVE-2022-48429_poc) :  ![starts](https://img.shields.io/github/stars/echo-devim/CVE-2022-48429_poc.svg) ![forks](https://img.shields.io/github/forks/echo-devim/CVE-2022-48429_poc.svg)


## CVE-2022-3368
 A vulnerability within the Software Updater functionality of Avira Security for Windows allowed an attacker with write access to the filesystem, to escalate his privileges in certain scenarios. The issue was fixed with Avira Security version 1.1.72.30556.

- [https://github.com/pxcs/CrackAVFee](https://github.com/pxcs/CrackAVFee) :  ![starts](https://img.shields.io/github/stars/pxcs/CrackAVFee.svg) ![forks](https://img.shields.io/github/forks/pxcs/CrackAVFee.svg)

