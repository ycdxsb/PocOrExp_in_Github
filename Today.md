# Update 2024-07-31
## CVE-2024-34693
 Improper Input Validation vulnerability in Apache Superset, allows for an authenticated attacker to create a MariaDB connection with local_infile enabled. If both the MariaDB server (off by default) and the local mysql client on the web server are set to allow for local infile, it's possible for the attacker to execute a specific MySQL/MariaDB SQL command that is able to read files from the server and insert their content on a MariaDB database table.This issue affects Apache Superset: before 3.1.3 and version 4.0.0 Users are recommended to upgrade to version 4.0.1 or 3.1.3, which fixes the issue.

- [https://github.com/labc-dev/CVE-2024-34693](https://github.com/labc-dev/CVE-2024-34693) :  ![starts](https://img.shields.io/github/stars/labc-dev/CVE-2024-34693.svg) ![forks](https://img.shields.io/github/forks/labc-dev/CVE-2024-34693.svg)


## CVE-2024-34144
 A sandbox bypass vulnerability involving crafted constructor bodies in Jenkins Script Security Plugin 1335.vf07d9ce377a_e and earlier allows attackers with permission to define and run sandboxed scripts, including Pipelines, to bypass the sandbox protection and execute arbitrary code in the context of the Jenkins controller JVM.

- [https://github.com/MXWXZ/CVE-2024-34144](https://github.com/MXWXZ/CVE-2024-34144) :  ![starts](https://img.shields.io/github/stars/MXWXZ/CVE-2024-34144.svg) ![forks](https://img.shields.io/github/forks/MXWXZ/CVE-2024-34144.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/charlesgargasson/CVE-2024-32002](https://github.com/charlesgargasson/CVE-2024-32002) :  ![starts](https://img.shields.io/github/stars/charlesgargasson/CVE-2024-32002.svg) ![forks](https://img.shields.io/github/forks/charlesgargasson/CVE-2024-32002.svg)


## CVE-2024-4162
 A buffer error in Panasonic KW Watcher versions 1.00 through 2.83 may allow attackers malicious read access to memory.

- [https://github.com/Redshift-CyberSecurity/CVE-2024-41628](https://github.com/Redshift-CyberSecurity/CVE-2024-41628) :  ![starts](https://img.shields.io/github/stars/Redshift-CyberSecurity/CVE-2024-41628.svg) ![forks](https://img.shields.io/github/forks/Redshift-CyberSecurity/CVE-2024-41628.svg)


## CVE-2024-4049
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Dirac231/CVE-2024-40498](https://github.com/Dirac231/CVE-2024-40498) :  ![starts](https://img.shields.io/github/stars/Dirac231/CVE-2024-40498.svg) ![forks](https://img.shields.io/github/forks/Dirac231/CVE-2024-40498.svg)


## CVE-2024-3992
 The Amen WordPress plugin through 3.3.1 does not sanitise and escape some of its settings, which could allow high privilege users such as admin to perform Stored Cross-Site Scripting attacks even when the unfiltered_html capability is disallowed (for example in multisite setup)

- [https://github.com/michael-david-fry/CVE-2024-39929](https://github.com/michael-david-fry/CVE-2024-39929) :  ![starts](https://img.shields.io/github/stars/michael-david-fry/CVE-2024-39929.svg) ![forks](https://img.shields.io/github/forks/michael-david-fry/CVE-2024-39929.svg)


## CVE-2024-3970
 Server Side Request Forgery vulnerability has been discovered in OpenText&#8482; iManager 3.2.6.0200. This could lead to senstive information disclosure by directory traversal.

- [https://github.com/10urc0de/CVE-2024-39700-PoC](https://github.com/10urc0de/CVE-2024-39700-PoC) :  ![starts](https://img.shields.io/github/stars/10urc0de/CVE-2024-39700-PoC.svg) ![forks](https://img.shields.io/github/forks/10urc0de/CVE-2024-39700-PoC.svg)


## CVE-2024-1071
 The Ultimate Member &#8211; User Profile, Registration, Login, Member Directory, Content Restriction &amp; Membership Plugin plugin for WordPress is vulnerable to SQL Injection via the 'sorting' parameter in versions 2.1.3 to 2.8.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/Matrexdz/CVE-2024-1071](https://github.com/Matrexdz/CVE-2024-1071) :  ![starts](https://img.shields.io/github/stars/Matrexdz/CVE-2024-1071.svg) ![forks](https://img.shields.io/github/forks/Matrexdz/CVE-2024-1071.svg)
- [https://github.com/Matrexdz/CVE-2024-1071-Docker](https://github.com/Matrexdz/CVE-2024-1071-Docker) :  ![starts](https://img.shields.io/github/stars/Matrexdz/CVE-2024-1071-Docker.svg) ![forks](https://img.shields.io/github/forks/Matrexdz/CVE-2024-1071-Docker.svg)


## CVE-2024-0049
 In multiple locations, there is a possible out of bounds write due to a heap buffer overflow. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0049](https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0049) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0049.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0049.svg)


## CVE-2024-0040
 In setParameter of MtpPacket.cpp, there is a possible out of bounds read due to a heap buffer overflow. This could lead to remote information disclosure with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0040](https://github.com/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0040) :  ![starts](https://img.shields.io/github/stars/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0040.svg) ![forks](https://img.shields.io/github/forks/nidhihcl75/frameworks_av_AOSP10_r33_CVE-2024-0040.svg)


## CVE-2024-0023
 In ConvertRGBToPlanarYUV of Codec2BufferUtils.cpp, there is a possible out of bounds write due to an incorrect bounds check. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/AbrarKhan/G3_Frameworks_av_CVE-2024-0023](https://github.com/AbrarKhan/G3_Frameworks_av_CVE-2024-0023) :  ![starts](https://img.shields.io/github/stars/AbrarKhan/G3_Frameworks_av_CVE-2024-0023.svg) ![forks](https://img.shields.io/github/forks/AbrarKhan/G3_Frameworks_av_CVE-2024-0023.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS &lt;= v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/insomnia-jacob/CVE-2023-4220](https://github.com/insomnia-jacob/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/insomnia-jacob/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/insomnia-jacob/CVE-2023-4220.svg)


## CVE-2023-3824
 In PHP version 8.0.* before 8.0.30, 8.1.* before 8.1.22, and 8.2.* before 8.2.8, when loading phar file, while reading PHAR directory entries, insufficient length checking may lead to a stack buffer overflow, leading potentially to memory corruption or RCE.

- [https://github.com/Nfttkcauzy/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK](https://github.com/Nfttkcauzy/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK) :  ![starts](https://img.shields.io/github/stars/Nfttkcauzy/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg) ![forks](https://img.shields.io/github/forks/Nfttkcauzy/CVE-2023-3824-PHP-to-RCE-LockBit-LEAK.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/skentagon/CVE-2021-41773](https://github.com/skentagon/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/skentagon/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/skentagon/CVE-2021-41773.svg)
- [https://github.com/Fa1c0n35/CVE-2021-41773](https://github.com/Fa1c0n35/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/CVE-2021-41773.svg)

