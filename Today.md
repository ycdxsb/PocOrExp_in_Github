# Update 2022-05-10
## CVE-2022-26809
 Remote Procedure Call Runtime Remote Code Execution Vulnerability. This CVE ID is unique from CVE-2022-24492, CVE-2022-24528.

- [https://github.com/seciurdt/CVE-2022-26809-POC](https://github.com/seciurdt/CVE-2022-26809-POC) :  ![starts](https://img.shields.io/github/stars/seciurdt/CVE-2022-26809-POC.svg) ![forks](https://img.shields.io/github/forks/seciurdt/CVE-2022-26809-POC.svg)


## CVE-2022-24734
 MyBB is a free and open source forum software. In affected versions the Admin CP's Settings management module does not validate setting types correctly on insertion and update, making it possible to add settings of supported type `php` with PHP code, executed on on _Change Settings_ pages. This results in a Remote Code Execution (RCE) vulnerability. The vulnerable module requires Admin CP access with the `Can manage settings?` permission. MyBB's Settings module, which allows administrators to add, edit, and delete non-default settings, stores setting data in an options code string ($options_code; mybb_settings.optionscode database column) that identifies the setting type and its options, separated by a new line character (\n). In MyBB 1.2.0, support for setting type php was added, for which the remaining part of the options code is PHP code executed on Change Settings pages (reserved for plugins and internal use). MyBB 1.8.30 resolves this issue. There are no known workarounds.

- [https://github.com/Altelus1/CVE-2022-24734](https://github.com/Altelus1/CVE-2022-24734) :  ![starts](https://img.shields.io/github/stars/Altelus1/CVE-2022-24734.svg) ![forks](https://img.shields.io/github/forks/Altelus1/CVE-2022-24734.svg)


## CVE-2022-1388
 On F5 BIG-IP 16.1.x versions prior to 16.1.2.2, 15.1.x versions prior to 15.1.5.1, 14.1.x versions prior to 14.1.4.6, 13.1.x versions prior to 13.1.5, and all 12.1.x and 11.6.x versions, undisclosed requests may bypass iControl REST authentication. Note: Software versions which have reached End of Technical Support (EoTS) are not evaluated

- [https://github.com/Hudi233/CVE-2022-1388](https://github.com/Hudi233/CVE-2022-1388) :  ![starts](https://img.shields.io/github/stars/Hudi233/CVE-2022-1388.svg) ![forks](https://img.shields.io/github/forks/Hudi233/CVE-2022-1388.svg)
- [https://github.com/blind-intruder/CVE-2022-1388-RCE-checker](https://github.com/blind-intruder/CVE-2022-1388-RCE-checker) :  ![starts](https://img.shields.io/github/stars/blind-intruder/CVE-2022-1388-RCE-checker.svg) ![forks](https://img.shields.io/github/forks/blind-intruder/CVE-2022-1388-RCE-checker.svg)


## CVE-2022-0847
 A flaw was found in the way the &quot;flags&quot; member of the new pipe buffer structure was lacking proper initialization in copy_page_to_iter_pipe and push_pipe functions in the Linux kernel and could thus contain stale values. An unprivileged local user could use this flaw to write to pages in the page cache backed by read only files and as such escalate their privileges on the system.

- [https://github.com/isaiahsimeone/COMP3320-VAPT](https://github.com/isaiahsimeone/COMP3320-VAPT) :  ![starts](https://img.shields.io/github/stars/isaiahsimeone/COMP3320-VAPT.svg) ![forks](https://img.shields.io/github/forks/isaiahsimeone/COMP3320-VAPT.svg)


## CVE-2019-10747
 set-value is vulnerable to Prototype Pollution in versions lower than 3.0.1. The function mixin-deep could be tricked into adding or modifying properties of Object.prototype using any of the constructor, prototype and _proto_ payloads.

- [https://github.com/ossf-cve-benchmark/CVE-2019-10747](https://github.com/ossf-cve-benchmark/CVE-2019-10747) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2019-10747.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2019-10747.svg)

