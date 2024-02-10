# Update 2024-02-10
## CVE-2023-30547
 vm2 is a sandbox that can run untrusted code with whitelisted Node's built-in modules. There exists a vulnerability in exception sanitization of vm2 for versions up to 3.9.16, allowing attackers to raise an unsanitized host exception inside `handleException()` which can be used to escape the sandbox and run arbitrary code in host context. This vulnerability was patched in the release of version `3.9.17` of `vm2`. There are no known workarounds for this vulnerability. Users are advised to upgrade.

- [https://github.com/user0x1337/CVE-2023-30547](https://github.com/user0x1337/CVE-2023-30547) :  ![starts](https://img.shields.io/github/stars/user0x1337/CVE-2023-30547.svg) ![forks](https://img.shields.io/github/forks/user0x1337/CVE-2023-30547.svg)


## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/MendDemo-josh/cve-2022-42889-text4shell](https://github.com/MendDemo-josh/cve-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/MendDemo-josh/cve-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/MendDemo-josh/cve-2022-42889-text4shell.svg)
- [https://github.com/joshbnewton31080/cve-2022-42889-text4shell](https://github.com/joshbnewton31080/cve-2022-42889-text4shell) :  ![starts](https://img.shields.io/github/stars/joshbnewton31080/cve-2022-42889-text4shell.svg) ![forks](https://img.shields.io/github/forks/joshbnewton31080/cve-2022-42889-text4shell.svg)


## CVE-2021-42013
 It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

- [https://github.com/OpenCVEs/CVE-2021-41773](https://github.com/OpenCVEs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/OpenCVEs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/OpenCVEs/CVE-2021-41773.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/OpenCVEs/CVE-2021-41773](https://github.com/OpenCVEs/CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/OpenCVEs/CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/OpenCVEs/CVE-2021-41773.svg)


## CVE-2021-32789
 woocommerce-gutenberg-products-block is a feature plugin for WooCommerce Gutenberg Blocks. An SQL injection vulnerability impacts all WooCommerce sites running the WooCommerce Blocks feature plugin between version 2.5.0 and prior to version 2.5.16. Via a carefully crafted URL, an exploit can be executed against the `wc/store/products/collection-data?calculate_attribute_counts[][taxonomy]` endpoint that allows the execution of a read only sql query. There are patches for many versions of this package, starting with version 2.5.16. There are no known workarounds aside from upgrading.

- [https://github.com/DonVorrin/CVE-2021-32789](https://github.com/DonVorrin/CVE-2021-32789) :  ![starts](https://img.shields.io/github/stars/DonVorrin/CVE-2021-32789.svg) ![forks](https://img.shields.io/github/forks/DonVorrin/CVE-2021-32789.svg)


## CVE-2021-4034
 A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is a setuid tool designed to allow unprivileged users to run commands as privileged users according predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly and ends trying to execute environment variables as commands. An attacker can leverage this by crafting environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully executed the attack can cause a local privilege escalation given unprivileged users administrative rights on the target machine.

- [https://github.com/OpenCVEs/CVE-2021-4034](https://github.com/OpenCVEs/CVE-2021-4034) :  ![starts](https://img.shields.io/github/stars/OpenCVEs/CVE-2021-4034.svg) ![forks](https://img.shields.io/github/forks/OpenCVEs/CVE-2021-4034.svg)


## CVE-2018-9995
 TBK DVR4104 and DVR4216 devices, as well as Novo, CeNova, QSee, Pulnix, XVR 5 in 1, Securus, Night OWL, DVR Login, HVR Login, and MDVR Login, which run re-branded versions of the original TBK DVR4104 and DVR4216 series, allow remote attackers to bypass authentication via a &quot;Cookie: uid=admin&quot; header, as demonstrated by a device.rsp?opt=user&amp;cmd=list request that provides credentials within JSON data in a response.

- [https://github.com/DOCKTYPe19/CVE-2018-9995](https://github.com/DOCKTYPe19/CVE-2018-9995) :  ![starts](https://img.shields.io/github/stars/DOCKTYPe19/CVE-2018-9995.svg) ![forks](https://img.shields.io/github/forks/DOCKTYPe19/CVE-2018-9995.svg)
- [https://github.com/arminarab1999/CVE-2018-9995](https://github.com/arminarab1999/CVE-2018-9995) :  ![starts](https://img.shields.io/github/stars/arminarab1999/CVE-2018-9995.svg) ![forks](https://img.shields.io/github/forks/arminarab1999/CVE-2018-9995.svg)

