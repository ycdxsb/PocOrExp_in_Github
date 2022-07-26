# Update 2022-07-26
## CVE-2022-34918
 An issue was discovered in the Linux kernel through 5.18.9. A type confusion bug in nft_set_elem_init (leading to a buffer overflow) could be used by a local attacker to escalate privileges, a different vulnerability than CVE-2022-32250. (The attacker can obtain root access, but must start with an unprivileged user namespace to obtain CAP_NET_ADMIN access.) This can be fixed in nft_setelem_parse_data in net/netfilter/nf_tables_api.c.

- [https://github.com/merlinepedra25/CVE-2022-34918-LPE-PoC](https://github.com/merlinepedra25/CVE-2022-34918-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/merlinepedra25/CVE-2022-34918-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/merlinepedra25/CVE-2022-34918-LPE-PoC.svg)
- [https://github.com/merlinepedra/CVE-2022-34918-LPE-PoC](https://github.com/merlinepedra/CVE-2022-34918-LPE-PoC) :  ![starts](https://img.shields.io/github/stars/merlinepedra/CVE-2022-34918-LPE-PoC.svg) ![forks](https://img.shields.io/github/forks/merlinepedra/CVE-2022-34918-LPE-PoC.svg)


## CVE-2022-33891
 The Apache Spark UI offers the possibility to enable ACLs via the configuration option spark.acls.enable. With an authentication filter, this checks whether a user has access permissions to view or modify the application. If ACLs are enabled, a code path in HttpSecurityFilter can allow someone to perform impersonation by providing an arbitrary user name. A malicious user might then be able to reach a permission check function that will ultimately build a Unix shell command based on their input, and execute it. This will result in arbitrary shell command execution as the user Spark is currently running as. This affects Apache Spark versions 3.0.3 and earlier, versions 3.1.1 to 3.1.2, and versions 3.2.0 to 3.2.1.

- [https://github.com/llraudseppll/cve-2022-33891](https://github.com/llraudseppll/cve-2022-33891) :  ![starts](https://img.shields.io/github/stars/llraudseppll/cve-2022-33891.svg) ![forks](https://img.shields.io/github/forks/llraudseppll/cve-2022-33891.svg)


## CVE-2022-32114
 An unrestricted file upload vulnerability in the Add New Assets function of Strapi v4.1.12 allows attackers to execute arbitrary code via a crafted file.

- [https://github.com/bypazs/CVE-2022-32114](https://github.com/bypazs/CVE-2022-32114) :  ![starts](https://img.shields.io/github/stars/bypazs/CVE-2022-32114.svg) ![forks](https://img.shields.io/github/forks/bypazs/CVE-2022-32114.svg)


## CVE-2022-31101
 prestashop/blockwishlist is a prestashop extension which adds a block containing the customer's wishlists. In affected versions an authenticated customer can perform SQL injection. This issue is fixed in version 2.1.1. Users are advised to upgrade. There are no known workarounds for this issue.

- [https://github.com/MathiasReker/blm-vlun](https://github.com/MathiasReker/blm-vlun) :  ![starts](https://img.shields.io/github/stars/MathiasReker/blm-vlun.svg) ![forks](https://img.shields.io/github/forks/MathiasReker/blm-vlun.svg)


## CVE-2022-24734
 MyBB is a free and open source forum software. In affected versions the Admin CP's Settings management module does not validate setting types correctly on insertion and update, making it possible to add settings of supported type `php` with PHP code, executed on on _Change Settings_ pages. This results in a Remote Code Execution (RCE) vulnerability. The vulnerable module requires Admin CP access with the `Can manage settings?` permission. MyBB's Settings module, which allows administrators to add, edit, and delete non-default settings, stores setting data in an options code string ($options_code; mybb_settings.optionscode database column) that identifies the setting type and its options, separated by a new line character (\n). In MyBB 1.2.0, support for setting type php was added, for which the remaining part of the options code is PHP code executed on Change Settings pages (reserved for plugins and internal use). MyBB 1.8.30 resolves this issue. There are no known workarounds.

- [https://github.com/Altelus1/CVE-2022-24734](https://github.com/Altelus1/CVE-2022-24734) :  ![starts](https://img.shields.io/github/stars/Altelus1/CVE-2022-24734.svg) ![forks](https://img.shields.io/github/forks/Altelus1/CVE-2022-24734.svg)


## CVE-2021-41184
 jQuery-UI is the official jQuery user interface library. Prior to version 1.13.0, accepting the value of the `of` option of the `.position()` util from untrusted sources may execute untrusted code. The issue is fixed in jQuery UI 1.13.0. Any string value passed to the `of` option is now treated as a CSS selector. A workaround is to not accept the value of the `of` option from untrusted sources.

- [https://github.com/gabrielolivra/Exploit-Medium-CVE-2021-41184](https://github.com/gabrielolivra/Exploit-Medium-CVE-2021-41184) :  ![starts](https://img.shields.io/github/stars/gabrielolivra/Exploit-Medium-CVE-2021-41184.svg) ![forks](https://img.shields.io/github/forks/gabrielolivra/Exploit-Medium-CVE-2021-41184.svg)


## CVE-2014-7169
 GNU Bash through 4.3 bash43-025 processes trailing strings after certain malformed function definitions in the values of environment variables, which allows remote attackers to write to files or possibly have unknown other impact via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2014-6271.

- [https://github.com/prince-stark/SHELL-SCHOCK](https://github.com/prince-stark/SHELL-SCHOCK) :  ![starts](https://img.shields.io/github/stars/prince-stark/SHELL-SCHOCK.svg) ![forks](https://img.shields.io/github/forks/prince-stark/SHELL-SCHOCK.svg)

