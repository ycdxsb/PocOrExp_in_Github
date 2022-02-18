# Update 2022-02-18
## CVE-2022-25265
 In the Linux kernel through 5.16.10, certain binary files may have the exec-all attribute if they were built in approximately 2003 (e.g., with GCC 3.2.2 and Linux kernel 2.4.20). This can cause execution of bytes located in supposedly non-executable regions of a file.

- [https://github.com/x0reaxeax/exec-prot-bypass](https://github.com/x0reaxeax/exec-prot-bypass) :  ![starts](https://img.shields.io/github/stars/x0reaxeax/exec-prot-bypass.svg) ![forks](https://img.shields.io/github/forks/x0reaxeax/exec-prot-bypass.svg)


## CVE-2022-24086
 Adobe Commerce versions 2.4.3-p1 (and earlier) and 2.3.7-p2 (and earlier) are affected by an improper input validation vulnerability during the checkout process. Exploitation of this issue does not require user interaction and could result in arbitrary code execution.

- [https://github.com/wambo-co/magento-1.9-cve-2022-24086](https://github.com/wambo-co/magento-1.9-cve-2022-24086) :  ![starts](https://img.shields.io/github/stars/wambo-co/magento-1.9-cve-2022-24086.svg) ![forks](https://img.shields.io/github/forks/wambo-co/magento-1.9-cve-2022-24086.svg)


## CVE-2020-27194
 An issue was discovered in the Linux kernel before 5.8.15. scalar32_min_max_or in kernel/bpf/verifier.c mishandles bounds tracking during use of 64-bit values, aka CID-5b9fbeb75b6a.

- [https://github.com/xmzyshypnc/CVE-2020-27194](https://github.com/xmzyshypnc/CVE-2020-27194) :  ![starts](https://img.shields.io/github/stars/xmzyshypnc/CVE-2020-27194.svg) ![forks](https://img.shields.io/github/forks/xmzyshypnc/CVE-2020-27194.svg)
- [https://github.com/willinin/CVE-2020-27194-exp](https://github.com/willinin/CVE-2020-27194-exp) :  ![starts](https://img.shields.io/github/stars/willinin/CVE-2020-27194-exp.svg) ![forks](https://img.shields.io/github/forks/willinin/CVE-2020-27194-exp.svg)


## CVE-2020-16126
 An Ubuntu-specific modification to AccountsService in versions before 0.6.55-0ubuntu13.2, among other earlier versions, improperly dropped the ruid, allowing untrusted users to send signals to AccountService, thus stopping it from handling D-Bus messages in a timely fashion.

- [https://github.com/zev3n/Ubuntu-Gnome-privilege-escalation](https://github.com/zev3n/Ubuntu-Gnome-privilege-escalation) :  ![starts](https://img.shields.io/github/stars/zev3n/Ubuntu-Gnome-privilege-escalation.svg) ![forks](https://img.shields.io/github/forks/zev3n/Ubuntu-Gnome-privilege-escalation.svg)


## CVE-2017-16651
 Roundcube Webmail before 1.1.10, 1.2.x before 1.2.7, and 1.3.x before 1.3.3 allows unauthorized access to arbitrary files on the host's filesystem, including configuration files, as exploited in the wild in November 2017. The attacker must be able to authenticate at the target system with a valid username/password as the attack requires an active session. The issue is related to file-based attachment plugins and _task=settings&amp;_action=upload-display&amp;_from=timezone requests.

- [https://github.com/ropbear/CVE-2017-16651](https://github.com/ropbear/CVE-2017-16651) :  ![starts](https://img.shields.io/github/stars/ropbear/CVE-2017-16651.svg) ![forks](https://img.shields.io/github/forks/ropbear/CVE-2017-16651.svg)


## CVE-2017-12635
 Due to differences in the Erlang-based JSON parser and JavaScript-based JSON parser, it is possible in Apache CouchDB before 1.7.0 and 2.x before 2.1.1 to submit _users documents with duplicate keys for 'roles' used for access control within the database, including the special case '_admin' role, that denotes administrative users. In combination with CVE-2017-12636 (Remote Code Execution), this can be used to give non-admin users access to arbitrary shell commands on the server as the database system user. The JSON parser differences result in behaviour that if two 'roles' keys are available in the JSON, the second one will be used for authorising the document write, but the first 'roles' key is used for subsequent authorization for the newly created user. By design, users can not assign themselves roles. The vulnerability allows non-admin users to give themselves admin privileges.

- [https://github.com/tranmanhdat/couchdb_cve-2017-12635](https://github.com/tranmanhdat/couchdb_cve-2017-12635) :  ![starts](https://img.shields.io/github/stars/tranmanhdat/couchdb_cve-2017-12635.svg) ![forks](https://img.shields.io/github/forks/tranmanhdat/couchdb_cve-2017-12635.svg)


## CVE-2017-6079
 The HTTP web-management application on Edgewater Networks Edgemarc appliances has a hidden page that allows for user-defined commands such as specific iptables routes, etc., to be set. You can use this page as a web shell essentially to execute commands, though you get no feedback client-side from the web application: if the command is valid, it executes. An example is the wget command. The page that allows this has been confirmed in firmware as old as 2006.

- [https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit](https://github.com/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit) :  ![starts](https://img.shields.io/github/stars/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg) ![forks](https://img.shields.io/github/forks/MostafaSoliman/CVE-2017-6079-Blind-Command-Injection-In-Edgewater-Edgemarc-Devices-Exploit.svg)


## CVE-2016-5195
 Race condition in mm/gup.c in the Linux kernel 2.x through 4.x before 4.8.3 allows local users to gain privileges by leveraging incorrect handling of a copy-on-write (COW) feature to write to a read-only memory mapping, as exploited in the wild in October 2016, aka &quot;Dirty COW.&quot;

- [https://github.com/th3-5had0w/DirtyCOW-PoC](https://github.com/th3-5had0w/DirtyCOW-PoC) :  ![starts](https://img.shields.io/github/stars/th3-5had0w/DirtyCOW-PoC.svg) ![forks](https://img.shields.io/github/forks/th3-5had0w/DirtyCOW-PoC.svg)


## CVE-2003-0282
 Directory traversal vulnerability in UnZip 5.50 allows attackers to overwrite arbitrary files via invalid characters between two . (dot) characters, which are filtered and result in a &quot;..&quot; sequence.

- [https://github.com/runtimem/cve-2003-0282](https://github.com/runtimem/cve-2003-0282) :  ![starts](https://img.shields.io/github/stars/runtimem/cve-2003-0282.svg) ![forks](https://img.shields.io/github/forks/runtimem/cve-2003-0282.svg)

