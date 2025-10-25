# Update 2025-10-25
## CVE-2025-62506
 MinIO is a high-performance object storage system. In all versions prior to RELEASE.2025-10-15T17-29-55Z, a privilege escalation vulnerability allows service accounts and STS (Security Token Service) accounts with restricted session policies to bypass their inline policy restrictions when performing operations on their own account, specifically when creating new service accounts for the same user. The vulnerability exists in the IAM policy validation logic where the code incorrectly relied on the DenyOnly argument when validating session policies for restricted accounts. When a session policy is present, the system should validate that the action is allowed by the session policy, not just that it is not denied. An attacker with valid credentials for a restricted service or STS account can create a new service account for itself without policy restrictions, resulting in a new service account with full parent privileges instead of being restricted by the inline policy. This allows the attacker to access buckets and objects beyond their intended restrictions and modify, delete, or create objects outside their authorized scope. The vulnerability is fixed in version RELEASE.2025-10-15T17-29-55Z.

- [https://github.com/yoshino-s/CVE-2025-62506](https://github.com/yoshino-s/CVE-2025-62506) :  ![starts](https://img.shields.io/github/stars/yoshino-s/CVE-2025-62506.svg) ![forks](https://img.shields.io/github/forks/yoshino-s/CVE-2025-62506.svg)


## CVE-2025-62481
 Vulnerability in the Oracle Marketing product of Oracle E-Business Suite (component: Marketing Administration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Marketing.  Successful attacks of this vulnerability can result in takeover of Oracle Marketing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/callinston/CVE-2025-62481](https://github.com/callinston/CVE-2025-62481) :  ![starts](https://img.shields.io/github/stars/callinston/CVE-2025-62481.svg) ![forks](https://img.shields.io/github/forks/callinston/CVE-2025-62481.svg)


## CVE-2025-61932
 Lanscope Endpoint Manager (On-Premises) (Client program (MR) and Detection agent (DA)) improperly verifies the origin of incoming requests, allowing an attacker to execute arbitrary code by sending specially crafted packets.

- [https://github.com/allinsthon/CVE-2025-61932](https://github.com/allinsthon/CVE-2025-61932) :  ![starts](https://img.shields.io/github/stars/allinsthon/CVE-2025-61932.svg) ![forks](https://img.shields.io/github/forks/allinsthon/CVE-2025-61932.svg)


## CVE-2025-61884
 Vulnerability in the Oracle Configurator product of Oracle E-Business Suite (component: Runtime UI).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Configurator.  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Configurator accessible data. CVSS 3.1 Base Score 7.5 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N).

- [https://github.com/pakagronglb/oracle-security-breaches-analysis-case-study](https://github.com/pakagronglb/oracle-security-breaches-analysis-case-study) :  ![starts](https://img.shields.io/github/stars/pakagronglb/oracle-security-breaches-analysis-case-study.svg) ![forks](https://img.shields.io/github/forks/pakagronglb/oracle-security-breaches-analysis-case-study.svg)


## CVE-2025-61882
 Vulnerability in the Oracle Concurrent Processing product of Oracle E-Business Suite (component: BI Publisher Integration).  Supported versions that are affected are 12.2.3-12.2.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Concurrent Processing.  Successful attacks of this vulnerability can result in takeover of Oracle Concurrent Processing. CVSS 3.1 Base Score 9.8 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).

- [https://github.com/godnish/CVE-2025-61882](https://github.com/godnish/CVE-2025-61882) :  ![starts](https://img.shields.io/github/stars/godnish/CVE-2025-61882.svg) ![forks](https://img.shields.io/github/forks/godnish/CVE-2025-61882.svg)
- [https://github.com/BattalionX/http-oracle-ebs-cve-2025-61882.nse](https://github.com/BattalionX/http-oracle-ebs-cve-2025-61882.nse) :  ![starts](https://img.shields.io/github/stars/BattalionX/http-oracle-ebs-cve-2025-61882.nse.svg) ![forks](https://img.shields.io/github/forks/BattalionX/http-oracle-ebs-cve-2025-61882.nse.svg)


## CVE-2025-60852
 A CSV Injection vulnerability existed in Instant Developer Foundation versions prior to 25.0.9600. Applications built with affected versions of the framework did not properly sanitize user-controlled input before including it in CSV exports. This issue could lead to code execution on the system where the exported CSV file is opened.

- [https://github.com/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC](https://github.com/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC) :  ![starts](https://img.shields.io/github/stars/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC.svg) ![forks](https://img.shields.io/github/forks/valeriocassoni/CSV-Injection-in-Instant-Developer-Foundation-25.0-PoC.svg)


## CVE-2025-48148
 Unrestricted Upload of File with Dangerous Type vulnerability in StoreKeeper B.V. StoreKeeper for WooCommerce allows Using Malicious Files. This issue affects StoreKeeper for WooCommerce: from n/a through 14.4.4.

- [https://github.com/Nxploited/CVE-2025-48148](https://github.com/Nxploited/CVE-2025-48148) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-48148.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-48148.svg)


## CVE-2025-29891
This CVE is related to the CVE-2025-27636: while they have the same root cause and are fixed with the same fix, CVE-2025-27636 was assumed to only be exploitable if an attacker could add malicious HTTP headers, while we have now determined that it is also exploitable via HTTP parameters. Like in CVE-2025-27636, exploitation is only possible if the Camel route uses particular vulnerable components.

- [https://github.com/Crystallen1/CVE-2025-29891-demo](https://github.com/Crystallen1/CVE-2025-29891-demo) :  ![starts](https://img.shields.io/github/stars/Crystallen1/CVE-2025-29891-demo.svg) ![forks](https://img.shields.io/github/forks/Crystallen1/CVE-2025-29891-demo.svg)


## CVE-2025-24813
Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

- [https://github.com/qzy0x/cve-2025-24813_poc](https://github.com/qzy0x/cve-2025-24813_poc) :  ![starts](https://img.shields.io/github/stars/qzy0x/cve-2025-24813_poc.svg) ![forks](https://img.shields.io/github/forks/qzy0x/cve-2025-24813_poc.svg)


## CVE-2025-11534
 The affected Raisecom devices allow SSH sessions to be established without completing user authentication. This could allow attackers to gain shell access without valid credentials.

- [https://github.com/DExplo1ted/CVE-2025-11534-POC](https://github.com/DExplo1ted/CVE-2025-11534-POC) :  ![starts](https://img.shields.io/github/stars/DExplo1ted/CVE-2025-11534-POC.svg) ![forks](https://img.shields.io/github/forks/DExplo1ted/CVE-2025-11534-POC.svg)


## CVE-2025-8088
     from ESET.

- [https://github.com/mocred/cve-2025-8088](https://github.com/mocred/cve-2025-8088) :  ![starts](https://img.shields.io/github/stars/mocred/cve-2025-8088.svg) ![forks](https://img.shields.io/github/forks/mocred/cve-2025-8088.svg)


## CVE-2025-6042
 The Lisfinity Core - Lisfinity Core plugin used for pebas® Lisfinity WordPress theme plugin for WordPress is vulnerable to privilege escalation in all versions up to, and including, 1.4.0. This is due to the plugin assigning the editor role by default. While limitations with respect to capabilities are put in place, use of the API is not restricted. This vulnerability can be leveraged together with CVE-2025-6038 to obtain admin privileges.

- [https://github.com/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425](https://github.com/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425) :  ![starts](https://img.shields.io/github/stars/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425.svg) ![forks](https://img.shields.io/github/forks/aakashtyal/Session-Persistence-After-Enabling-2FA-CVE-2025-60425.svg)
- [https://github.com/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424](https://github.com/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424) :  ![starts](https://img.shields.io/github/stars/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424.svg) ![forks](https://img.shields.io/github/forks/aakashtyal/2FA-Bypass-using-a-Brute-Force-Attack-CVE-2025-60424.svg)


## CVE-2024-56800
 Firecrawl is a web scraper that allows users to extract the content of a webpage for a large language model. Versions prior to 1.1.1 contain a server-side request forgery (SSRF) vulnerability. The scraping engine could be exploited by crafting a malicious site that redirects to a local IP address. This allowed exfiltration of local network resources through the API. The cloud service was patched on December 27th, 2024, and the maintainers have checked that no user data was exposed by this vulnerability. Scraping engines used in the open sourced version of Firecrawl were patched on December 29th, 2024, except for the playwright services which the maintainers have determined to be un-patchable. All users of open-source software (OSS) Firecrawl should upgrade to v1.1.1. As a workaround, OSS Firecrawl users should supply the playwright services with a secure proxy. A proxy can be specified through the `PROXY_SERVER` env in the environment variables. Please refer to the documentation for instructions. Ensure that the proxy server one is using is setup to block all traffic going to link-local IP addresses.

- [https://github.com/cyhe50/cve-2024-56800-poc](https://github.com/cyhe50/cve-2024-56800-poc) :  ![starts](https://img.shields.io/github/stars/cyhe50/cve-2024-56800-poc.svg) ![forks](https://img.shields.io/github/forks/cyhe50/cve-2024-56800-poc.svg)


## CVE-2024-38063
 Windows TCP/IP Remote Code Execution Vulnerability

- [https://github.com/akozsentre/CVE-2024-38063](https://github.com/akozsentre/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/akozsentre/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/akozsentre/CVE-2024-38063.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/mystxcal/cve-2024-32002-demo](https://github.com/mystxcal/cve-2024-32002-demo) :  ![starts](https://img.shields.io/github/stars/mystxcal/cve-2024-32002-demo.svg) ![forks](https://img.shields.io/github/forks/mystxcal/cve-2024-32002-demo.svg)


## CVE-2021-26855
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/r0xDB/CVE-2021-26855](https://github.com/r0xDB/CVE-2021-26855) :  ![starts](https://img.shields.io/github/stars/r0xDB/CVE-2021-26855.svg) ![forks](https://img.shields.io/github/forks/r0xDB/CVE-2021-26855.svg)


## CVE-2021-24098
 Windows Console Driver Denial of Service Vulnerability

- [https://github.com/waleedassar/CVE-2021-24098](https://github.com/waleedassar/CVE-2021-24098) :  ![starts](https://img.shields.io/github/stars/waleedassar/CVE-2021-24098.svg) ![forks](https://img.shields.io/github/forks/waleedassar/CVE-2021-24098.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux](https://github.com/teelrabbit/Polkit-pkexec-exploit-for-Linux) :  ![starts](https://img.shields.io/github/stars/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg) ![forks](https://img.shields.io/github/forks/teelrabbit/Polkit-pkexec-exploit-for-Linux.svg)


## CVE-2020-11978
 An issue was found in Apache Airflow versions 1.10.10 and below. A remote code/command injection vulnerability was discovered in one of the example DAGs shipped with Airflow which would allow any authenticated user to run arbitrary commands as the user running airflow worker/scheduler (depending on the executor in use). If you already have examples disabled by setting load_examples=False in the config then you are not vulnerable.

- [https://github.com/stuxbench/mlflow-cve-2020-11978](https://github.com/stuxbench/mlflow-cve-2020-11978) :  ![starts](https://img.shields.io/github/stars/stuxbench/mlflow-cve-2020-11978.svg) ![forks](https://img.shields.io/github/forks/stuxbench/mlflow-cve-2020-11978.svg)


## CVE-2020-10987
 The goform/setUsbUnload endpoint of Tenda AC15 AC1900 version 15.03.05.19 allows remote attackers to execute arbitrary system commands via the deviceName POST parameter.

- [https://github.com/Jaden-Bowers/Tenda-Router-VR-and-Exploit](https://github.com/Jaden-Bowers/Tenda-Router-VR-and-Exploit) :  ![starts](https://img.shields.io/github/stars/Jaden-Bowers/Tenda-Router-VR-and-Exploit.svg) ![forks](https://img.shields.io/github/forks/Jaden-Bowers/Tenda-Router-VR-and-Exploit.svg)


## CVE-2019-18935
 Progress Telerik UI for ASP.NET AJAX through 2019.3.1023 contains a .NET deserialization vulnerability in the RadAsyncUpload function. This is exploitable when the encryption keys are known due to the presence of CVE-2017-11317 or CVE-2017-11357, or other means. Exploitation can result in remote code execution. (As of 2020.1.114, a default setting prevents the exploit. In 2019.3.1023, but not earlier versions, a non-default setting can prevent exploitation.)

- [https://github.com/menashe12346/CVE-2019-18935](https://github.com/menashe12346/CVE-2019-18935) :  ![starts](https://img.shields.io/github/stars/menashe12346/CVE-2019-18935.svg) ![forks](https://img.shields.io/github/forks/menashe12346/CVE-2019-18935.svg)


## CVE-2019-11043
 In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24 and 7.3.x below 7.3.11 in certain configurations of FPM setup it is possible to cause FPM module to write past allocated buffers into the space reserved for FCGI protocol data, thus opening the possibility of remote code execution.

- [https://github.com/CodeHex083/phuip-fpizdam](https://github.com/CodeHex083/phuip-fpizdam) :  ![starts](https://img.shields.io/github/stars/CodeHex083/phuip-fpizdam.svg) ![forks](https://img.shields.io/github/forks/CodeHex083/phuip-fpizdam.svg)


## CVE-2014-3120
 The default configuration in Elasticsearch before 1.2 enables dynamic scripting, which allows remote attackers to execute arbitrary MVEL expressions and Java code via the source parameter to _search.  NOTE: this only violates the vendor's intended security policy if the user does not run Elasticsearch in its own independent virtual machine.

- [https://github.com/echohtp/ElasticSearch-CVE-2014-3120](https://github.com/echohtp/ElasticSearch-CVE-2014-3120) :  ![starts](https://img.shields.io/github/stars/echohtp/ElasticSearch-CVE-2014-3120.svg) ![forks](https://img.shields.io/github/forks/echohtp/ElasticSearch-CVE-2014-3120.svg)
- [https://github.com/jeffgeiger/es_inject](https://github.com/jeffgeiger/es_inject) :  ![starts](https://img.shields.io/github/stars/jeffgeiger/es_inject.svg) ![forks](https://img.shields.io/github/forks/jeffgeiger/es_inject.svg)
- [https://github.com/xpgdgit/CVE-2014-3120](https://github.com/xpgdgit/CVE-2014-3120) :  ![starts](https://img.shields.io/github/stars/xpgdgit/CVE-2014-3120.svg) ![forks](https://img.shields.io/github/forks/xpgdgit/CVE-2014-3120.svg)

