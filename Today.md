# Update 2022-09-10
## CVE-2022-34265
 An issue was discovered in Django 3.2 before 3.2.14 and 4.0 before 4.0.6. The Trunc() and Extract() database functions are subject to SQL injection if untrusted data is used as a kind/lookup_name value. Applications that constrain the lookup name and kind choice to a known safe list are unaffected.

- [https://github.com/coco0x0a/CTF_CVE-2022-34265](https://github.com/coco0x0a/CTF_CVE-2022-34265) :  ![starts](https://img.shields.io/github/stars/coco0x0a/CTF_CVE-2022-34265.svg) ![forks](https://img.shields.io/github/forks/coco0x0a/CTF_CVE-2022-34265.svg)


## CVE-2022-20126
 In setScanMode of AdapterService.java, there is a possible way to enable Bluetooth discovery mode without user interaction due to a missing permission check. This could lead to local escalation of privilege with User execution privileges needed. User interaction is needed for exploitation.Product: AndroidVersions: Android-10 Android-11 Android-12 Android-12LAndroid ID: A-203431023

- [https://github.com/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126](https://github.com/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126) :  ![starts](https://img.shields.io/github/stars/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126.svg) ![forks](https://img.shields.io/github/forks/Trinadh465/packages_apps_Bluetooth_AOSP10_r33_CVE-2022-20126.svg)


## CVE-2021-38314
 The Gutenberg Template Library &amp; Redux Framework plugin &lt;= 4.2.11 for WordPress registered several AJAX actions available to unauthenticated users in the `includes` function in `redux-core/class-redux-core.php` that were unique to a given site but deterministic and predictable given that they were based on an md5 hash of the site URL with a known salt value of '-redux' and an md5 hash of the previous hash with a known salt value of '-support'. These AJAX actions could be used to retrieve a list of active plugins and their versions, the site's PHP version, and an unsalted md5 hash of site&#8217;s `AUTH_KEY` concatenated with the `SECURE_AUTH_KEY`.

- [https://github.com/akhilkoradiya/CVE-2021-38314](https://github.com/akhilkoradiya/CVE-2021-38314) :  ![starts](https://img.shields.io/github/stars/akhilkoradiya/CVE-2021-38314.svg) ![forks](https://img.shields.io/github/forks/akhilkoradiya/CVE-2021-38314.svg)


## CVE-2021-3493
 The overlayfs implementation in the linux kernel did not properly validate with respect to user namespaces the setting of file capabilities on files in an underlying file system. Due to the combination of unprivileged user namespaces along with a patch carried in the Ubuntu kernel to allow unprivileged overlay mounts, an attacker could use this to gain elevated privileges.

- [https://github.com/inspiringz/CVE-2021-3493](https://github.com/inspiringz/CVE-2021-3493) :  ![starts](https://img.shields.io/github/stars/inspiringz/CVE-2021-3493.svg) ![forks](https://img.shields.io/github/forks/inspiringz/CVE-2021-3493.svg)


## CVE-2014-6271
 GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment, as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified DHCP clients, and other situations in which setting the environment occurs across a privilege boundary from Bash execution, aka &quot;ShellShock.&quot;  NOTE: the original fix for this issue was incorrect; CVE-2014-7169 has been assigned to cover the vulnerability that is still present after the incorrect fix.

- [https://github.com/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-](https://github.com/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-) :  ![starts](https://img.shields.io/github/stars/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-.svg) ![forks](https://img.shields.io/github/forks/FilipStudeny/-CVE-2014-6271-Shellshock-Remote-Command-Injection-.svg)

