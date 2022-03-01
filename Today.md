# Update 2022-03-01
## CVE-2022-23131
 In the case of instances where the SAML SSO authentication is enabled (non-default), session data can be modified by a malicious actor, because a user login stored in the session was not verified. Malicious unauthenticated actor may exploit this issue to escalate privileges and gain admin access to Zabbix Frontend. To perform the attack, SAML authentication is required to be enabled and the actor has to know the username of Zabbix user (or use the guest account, which is disabled by default).

- [https://github.com/Fa1c0n35/zabbix-cve-2022-23131](https://github.com/Fa1c0n35/zabbix-cve-2022-23131) :  ![starts](https://img.shields.io/github/stars/Fa1c0n35/zabbix-cve-2022-23131.svg) ![forks](https://img.shields.io/github/forks/Fa1c0n35/zabbix-cve-2022-23131.svg)


## CVE-2022-0185
 A heap-based buffer overflow flaw was found in the way the legacy_parse_param function in the Filesystem Context functionality of the Linux kernel verified the supplied parameters length. An unprivileged (in case of unprivileged user namespaces enabled, otherwise needs namespaced CAP_SYS_ADMIN privilege) local user able to open a filesystem that does not support the Filesystem Context API (and thus fallbacks to legacy handling) could use this flaw to escalate their privileges on the system.

- [https://github.com/shahparkhan/cve-2022-0185](https://github.com/shahparkhan/cve-2022-0185) :  ![starts](https://img.shields.io/github/stars/shahparkhan/cve-2022-0185.svg) ![forks](https://img.shields.io/github/forks/shahparkhan/cve-2022-0185.svg)


## CVE-2019-19699
 There is Authenticated remote code execution in Centreon Infrastructure Monitoring Software through 19.10 via Pollers misconfiguration, leading to system compromise via apache crontab misconfiguration, This allows the apache user to modify an executable file executed by root at 22:30 every day. To exploit the vulnerability, someone must have Admin access to the Centreon Web Interface and create a custom main.php?p=60803&amp;type=3 command. The user must then set the Pollers Post-Restart Command to this previously created command via the main.php?p=60901&amp;o=c&amp;server_id=1 URI. This is triggered via an export of the Poller Configuration.

- [https://github.com/SpengeSec/CVE-2019-19699](https://github.com/SpengeSec/CVE-2019-19699) :  ![starts](https://img.shields.io/github/stars/SpengeSec/CVE-2019-19699.svg) ![forks](https://img.shields.io/github/forks/SpengeSec/CVE-2019-19699.svg)


## CVE-2019-2215
 A use-after-free in binder.c allows an elevation of privilege from an application to the Linux Kernel. No user interaction is required to exploit this vulnerability, however exploitation does require either the installation of a malicious local application or a separate vulnerability in a network facing application.Product: AndroidAndroid ID: A-141720095

- [https://github.com/nicchongwb/Rootsmart-v2.0](https://github.com/nicchongwb/Rootsmart-v2.0) :  ![starts](https://img.shields.io/github/stars/nicchongwb/Rootsmart-v2.0.svg) ![forks](https://img.shields.io/github/forks/nicchongwb/Rootsmart-v2.0.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/readloud/CVE-2017-5638](https://github.com/readloud/CVE-2017-5638) :  ![starts](https://img.shields.io/github/stars/readloud/CVE-2017-5638.svg) ![forks](https://img.shields.io/github/forks/readloud/CVE-2017-5638.svg)

