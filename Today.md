# Update 2023-04-04
## CVE-2023-28432
 Minio is a Multi-Cloud Object Storage framework. In a cluster deployment starting with RELEASE.2019-12-17T23-16-33Z and prior to RELEASE.2023-03-20T20-16-18Z, MinIO returns all environment variables, including `MINIO_SECRET_KEY` and `MINIO_ROOT_PASSWORD`, resulting in information disclosure. All users of distributed deployment are impacted. All users are advised to upgrade to RELEASE.2023-03-20T20-16-18Z.

- [https://github.com/7a6163/CVE-2023-28432](https://github.com/7a6163/CVE-2023-28432) :  ![starts](https://img.shields.io/github/stars/7a6163/CVE-2023-28432.svg) ![forks](https://img.shields.io/github/forks/7a6163/CVE-2023-28432.svg)


## CVE-2021-45105
 Apache Log4j2 versions 2.0-alpha1 through 2.16.0 (excluding 2.12.3 and 2.3.1) did not protect from uncontrolled recursion from self-referential lookups. This allows an attacker with control over Thread Context Map data to cause a denial of service when a crafted string is interpreted. This issue was fixed in Log4j 2.17.0, 2.12.3, and 2.3.1.

- [https://github.com/demonrvm/Log4ShellRemediation](https://github.com/demonrvm/Log4ShellRemediation) :  ![starts](https://img.shields.io/github/stars/demonrvm/Log4ShellRemediation.svg) ![forks](https://img.shields.io/github/forks/demonrvm/Log4ShellRemediation.svg)


## CVE-2021-45046
 It was found that the fix to address CVE-2021-44228 in Apache Log4j 2.15.0 was incomplete in certain non-default configurations. This could allows attackers with control over Thread Context Map (MDC) input data when the logging configuration uses a non-default Pattern Layout with either a Context Lookup (for example, $${ctx:loginId}) or a Thread Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data using a JNDI Lookup pattern resulting in an information leak and remote code execution in some environments and local code execution in all environments. Log4j 2.16.0 (Java 8) and 2.12.2 (Java 7) fix this issue by removing support for message lookup patterns and disabling JNDI functionality by default.

- [https://github.com/demonrvm/Log4ShellRemediation](https://github.com/demonrvm/Log4ShellRemediation) :  ![starts](https://img.shields.io/github/stars/demonrvm/Log4ShellRemediation.svg) ![forks](https://img.shields.io/github/forks/demonrvm/Log4ShellRemediation.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/xcanwin/CVE-2021-4034-UniontechOS](https://github.com/xcanwin/CVE-2021-4034-UniontechOS) :  ![starts](https://img.shields.io/github/stars/xcanwin/CVE-2021-4034-UniontechOS.svg) ![forks](https://img.shields.io/github/forks/xcanwin/CVE-2021-4034-UniontechOS.svg)


## CVE-2020-17530
 Forced OGNL evaluation, when evaluated on raw user input in tag attributes, may lead to remote code execution. Affected software : Apache Struts 2.0.0 - Struts 2.5.25.

- [https://github.com/keyuan15/CVE-2020-17530](https://github.com/keyuan15/CVE-2020-17530) :  ![starts](https://img.shields.io/github/stars/keyuan15/CVE-2020-17530.svg) ![forks](https://img.shields.io/github/forks/keyuan15/CVE-2020-17530.svg)


## CVE-2020-2553
 Vulnerability in the Oracle Knowledge product of Oracle Knowledge (component: Information Manager Console). Supported versions that are affected are 8.6.0-8.6.3. Difficult to exploit vulnerability allows unauthenticated attacker with network access via HTTP to compromise Oracle Knowledge. Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Knowledge accessible data as well as unauthorized read access to a subset of Oracle Knowledge accessible data. CVSS 3.0 Base Score 4.8 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

- [https://github.com/5l1v3r1/CVE-2020-2553](https://github.com/5l1v3r1/CVE-2020-2553) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-2553.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-2553.svg)


## CVE-2016-10993
 The ScoreMe theme through 2016-04-01 for WordPress has XSS via the s parameter.

- [https://github.com/VarelSecurity/CVE-2016-10993](https://github.com/VarelSecurity/CVE-2016-10993) :  ![starts](https://img.shields.io/github/stars/VarelSecurity/CVE-2016-10993.svg) ![forks](https://img.shields.io/github/forks/VarelSecurity/CVE-2016-10993.svg)

