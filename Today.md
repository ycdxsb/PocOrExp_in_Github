# Update 2022-05-26
## CVE-2022-30781
 Gitea before 1.16.7 does not escape git fetch remote.

- [https://github.com/wuhan005/CVE-2022-30781](https://github.com/wuhan005/CVE-2022-30781) :  ![starts](https://img.shields.io/github/stars/wuhan005/CVE-2022-30781.svg) ![forks](https://img.shields.io/github/forks/wuhan005/CVE-2022-30781.svg)


## CVE-2022-25235
 xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks for whether a UTF-8 character is valid in a certain context.

- [https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25235](https://github.com/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25235) :  ![starts](https://img.shields.io/github/stars/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25235.svg) ![forks](https://img.shields.io/github/forks/Satheesh575555/external_expat_AOSP10_r33_CVE-2022-25235.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/jheeree/CVE-2022-1388-checker](https://github.com/jheeree/CVE-2022-1388-checker) :  ![starts](https://img.shields.io/github/stars/jheeree/CVE-2022-1388-checker.svg) ![forks](https://img.shields.io/github/forks/jheeree/CVE-2022-1388-checker.svg)


## CVE-2022-1292
 The c_rehash script does not properly sanitise shell metacharacters to prevent command injection. This script is distributed by some operating systems in a manner where it is automatically executed. On such operating systems, an attacker could execute arbitrary commands with the privileges of the script. Use of the c_rehash script is considered obsolete and should be replaced by the OpenSSL rehash command line tool. Fixed in OpenSSL 3.0.3 (Affected 3.0.0,3.0.1,3.0.2). Fixed in OpenSSL 1.1.1o (Affected 1.1.1-1.1.1n). Fixed in OpenSSL 1.0.2ze (Affected 1.0.2-1.0.2zd).

- [https://github.com/li8u99/CVE-2022-1292](https://github.com/li8u99/CVE-2022-1292) :  ![starts](https://img.shields.io/github/stars/li8u99/CVE-2022-1292.svg) ![forks](https://img.shields.io/github/forks/li8u99/CVE-2022-1292.svg)


## CVE-2021-46422
 Telesquare SDT-CW3B1 1.1.0 is affected by an OS command injection vulnerability that allows a remote attacker to execute OS commands without any authentication.

- [https://github.com/nobodyatall648/CVE-2021-46422](https://github.com/nobodyatall648/CVE-2021-46422) :  ![starts](https://img.shields.io/github/stars/nobodyatall648/CVE-2021-46422.svg) ![forks](https://img.shields.io/github/forks/nobodyatall648/CVE-2021-46422.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/luckythandel/CVE-2021-4034](https://github.com/luckythandel/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/luckythandel/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/luckythandel/CVE-2021-4034.svg)
- [https://github.com/ziadsaleemi/polkit_CVE-2021-4034](https://github.com/ziadsaleemi/polkit_CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/ziadsaleemi/polkit_CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/ziadsaleemi/polkit_CVE-2021-4034.svg)
- [https://github.com/TomSgn/CVE-2021-4034](https://github.com/TomSgn/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/TomSgn/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/TomSgn/CVE-2021-4034.svg)


## CVE-2020-29597
 IncomCMS 2.0 has a modules/uploader/showcase/script.php insecure file upload vulnerability. This vulnerability allows unauthenticated attackers to upload files into the server.

- [https://github.com/trhacknon/CVE-2020-29597](https://github.com/trhacknon/CVE-2020-29597) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2020-29597.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2020-29597.svg)


## CVE-2020-26233
 Git Credential Manager Core (GCM Core) is a secure Git credential helper built on .NET Core that runs on Windows and macOS. In Git Credential Manager Core before version 2.0.289, when recursively cloning a Git repository on Windows with submodules, Git will first clone the top-level repository and then recursively clone all submodules by starting new Git processes from the top-level working directory. If a malicious git.exe executable is present in the top-level repository then this binary will be started by Git Credential Manager Core when attempting to read configuration, and not git.exe as found on the %PATH%. This only affects GCM Core on Windows, not macOS or Linux-based distributions. GCM Core version 2.0.289 contains the fix for this vulnerability, and is available from the project's GitHub releases page. GCM Core 2.0.289 is also bundled in the latest Git for Windows release; version 2.29.2(3). As a workaround, users should avoid recursively cloning untrusted repositories with the --recurse-submodules option.

- [https://github.com/whr819987540/test_CVE-2020-26233](https://github.com/whr819987540/test_CVE-2020-26233) :  ![starts](https://img.shields.io/github/stars/whr819987540/test_CVE-2020-26233.svg) ![forks](https://img.shields.io/github/forks/whr819987540/test_CVE-2020-26233.svg)


## CVE-2020-25213
 The File Manager (wp-file-manager) plugin before 6.9 for WordPress allows remote attackers to upload and execute arbitrary PHP code because it renames an unsafe example elFinder connector file to have the .php extension. This, for example, allows attackers to run the elFinder upload (or mkfile and put) command to write PHP code into the wp-content/plugins/wp-file-manager/lib/files/ directory. This was exploited in the wild in August and September 2020.

- [https://github.com/b1ackros337/CVE-2020-25213](https://github.com/b1ackros337/CVE-2020-25213) :  ![starts](https://img.shields.io/github/stars/b1ackros337/CVE-2020-25213.svg) ![forks](https://img.shields.io/github/forks/b1ackros337/CVE-2020-25213.svg)


## CVE-2020-11023
 In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing &lt;option&gt; elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2020-11023](https://github.com/Snorlyd/https-nj.gov---CVE-2020-11023) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2020-11023.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2020-11023.svg)


## CVE-2020-11022
 In jQuery versions greater than or equal to 1.2 and before 3.5.0, passing HTML from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.

- [https://github.com/Snorlyd/https-nj.gov---CVE-2020-11022](https://github.com/Snorlyd/https-nj.gov---CVE-2020-11022) :  ![starts](https://img.shields.io/github/stars/Snorlyd/https-nj.gov---CVE-2020-11022.svg) ![forks](https://img.shields.io/github/forks/Snorlyd/https-nj.gov---CVE-2020-11022.svg)

