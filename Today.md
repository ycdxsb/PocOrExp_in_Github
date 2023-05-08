# Update 2023-05-08
## CVE-2023-29007
 Git is a revision control system. Prior to versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1, a specially crafted `.gitmodules` file with submodule URLs that are longer than 1024 characters can used to exploit a bug in `config.c::git_config_copy_or_rename_section_in_file()`. This bug can be used to inject arbitrary configuration into a user's `$GIT_DIR/config` when attempting to remove the configuration section associated with that submodule. When the attacker injects configuration values which specify executables to run (such as `core.pager`, `core.editor`, `core.sshCommand`, etc.) this can lead to a remote code execution. A fix A fix is available in versions 2.30.9, 2.31.8, 2.32.7, 2.33.8, 2.34.8, 2.35.8, 2.36.6, 2.37.7, 2.38.5, 2.39.3, and 2.40.1. As a workaround, avoid running `git submodule deinit` on untrusted repositories or without prior inspection of any submodule sections in `$GIT_DIR/config`.

- [https://github.com/x-Defender/CVE-2023-29007_win-version](https://github.com/x-Defender/CVE-2023-29007_win-version) :  ![starts](https://img.shields.io/github/stars/x-Defender/CVE-2023-29007_win-version.svg) ![forks](https://img.shields.io/github/forks/x-Defender/CVE-2023-29007_win-version.svg)


## CVE-2023-24709
 An issue found in Paradox Security Systems IPR512 allows attackers to cause a denial of service via the login.html and login.xml parameters.

- [https://github.com/DRAGOWN/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC](https://github.com/DRAGOWN/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC) :  ![starts](https://img.shields.io/github/stars/DRAGOWN/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC.svg) ![forks](https://img.shields.io/github/forks/DRAGOWN/Injection-vulnerability-in-Paradox-Security-Systems-IPR512-CVE-2023-24709-PoC.svg)


## CVE-2023-0386
 A flaw was found in the Linux kernel, where unauthorized access to the execution of the setuid file with capabilities was found in the Linux kernel&#8217;s OverlayFS subsystem in how a user copies a capable file from a nosuid mount into another mount. This uid mapping bug allows a local user to escalate their privileges on the system.

- [https://github.com/chenaotian/CVE-2023-0386](https://github.com/chenaotian/CVE-2023-0386) :  ![starts](https://img.shields.io/github/stars/chenaotian/CVE-2023-0386.svg) ![forks](https://img.shields.io/github/forks/chenaotian/CVE-2023-0386.svg)


## CVE-2022-41034
 Visual Studio Code Remote Code Execution Vulnerability.

- [https://github.com/andyhsu024/CVE-2022-41034](https://github.com/andyhsu024/CVE-2022-41034) :  ![starts](https://img.shields.io/github/stars/andyhsu024/CVE-2022-41034.svg) ![forks](https://img.shields.io/github/forks/andyhsu024/CVE-2022-41034.svg)


## CVE-2022-21907
 HTTP Protocol Stack Remote Code Execution Vulnerability.

- [https://github.com/EzoomE/CVE-2022-21907-RCE](https://github.com/EzoomE/CVE-2022-21907-RCE) :  ![starts](https://img.shields.io/github/stars/EzoomE/CVE-2022-21907-RCE.svg) ![forks](https://img.shields.io/github/forks/EzoomE/CVE-2022-21907-RCE.svg)


## CVE-2021-46703
 ** UNSUPPORTED WHEN ASSIGNED ** In the IsolatedRazorEngine component of Antaris RazorEngine through 4.5.1-alpha001, an attacker can execute arbitrary .NET code in a sandboxed environment (if users can externally control template contents). NOTE: This vulnerability only affects products that are no longer supported by the maintainer.

- [https://github.com/BenEdridge/CVE-2021-46703](https://github.com/BenEdridge/CVE-2021-46703) :  ![starts](https://img.shields.io/github/stars/BenEdridge/CVE-2021-46703.svg) ![forks](https://img.shields.io/github/forks/BenEdridge/CVE-2021-46703.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC), aka 'Netlogon Elevation of Privilege Vulnerability'.

- [https://github.com/guglia001/MassZeroLogon](https://github.com/guglia001/MassZeroLogon) :  ![starts](https://img.shields.io/github/stars/guglia001/MassZeroLogon.svg) ![forks](https://img.shields.io/github/forks/guglia001/MassZeroLogon.svg)


## CVE-2020-1350
 A remote code execution vulnerability exists in Windows Domain Name System servers when they fail to properly handle requests, aka 'Windows DNS Server Remote Code Execution Vulnerability'.

- [https://github.com/captainGeech42/CVE-2020-1350](https://github.com/captainGeech42/CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/captainGeech42/CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/captainGeech42/CVE-2020-1350.svg)
- [https://github.com/zoomerxsec/Fake_CVE-2020-1350](https://github.com/zoomerxsec/Fake_CVE-2020-1350) :  ![starts](https://img.shields.io/github/stars/zoomerxsec/Fake_CVE-2020-1350.svg) ![forks](https://img.shields.io/github/forks/zoomerxsec/Fake_CVE-2020-1350.svg)


## CVE-2017-5689
 An unprivileged network attacker could gain system privileges to provisioned Intel manageability SKUs: Intel Active Management Technology (AMT) and Intel Standard Manageability (ISM). An unprivileged local attacker could provision manageability features gaining unprivileged network or local system privileges on Intel manageability SKUs: Intel Active Management Technology (AMT), Intel Standard Manageability (ISM), and Intel Small Business Technology (SBT).

- [https://github.com/odx686/CVE-2017-5689](https://github.com/odx686/CVE-2017-5689) :  ![starts](https://img.shields.io/github/stars/odx686/CVE-2017-5689.svg) ![forks](https://img.shields.io/github/forks/odx686/CVE-2017-5689.svg)


## CVE-2017-5487
 wp-includes/rest-api/endpoints/class-wp-rest-users-controller.php in the REST API implementation in WordPress 4.7 before 4.7.1 does not properly restrict listings of post authors, which allows remote attackers to obtain sensitive information via a wp-json/wp/v2/users request.

- [https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2017-5487-EXPLOIT) :  ![starts](https://img.shields.io/github/stars/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg) ![forks](https://img.shields.io/github/forks/K3ysTr0K3R/CVE-2017-5487-EXPLOIT.svg)


## CVE-2016-10045
 The isMail transport in PHPMailer before 5.2.20 might allow remote attackers to pass extra parameters to the mail command and consequently execute arbitrary code by leveraging improper interaction between the escapeshellarg function and internal escaping performed in the mail function in PHP. NOTE: this vulnerability exists because of an incorrect fix for CVE-2016-10033.

- [https://github.com/Zenexer/safeshell](https://github.com/Zenexer/safeshell) :  ![starts](https://img.shields.io/github/stars/Zenexer/safeshell.svg) ![forks](https://img.shields.io/github/forks/Zenexer/safeshell.svg)

