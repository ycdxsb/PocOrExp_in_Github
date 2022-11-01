# Update 2022-11-01
## CVE-2022-42889
 Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Text 1.10.0, which disables the problematic interpolators by default.

- [https://github.com/YulinSec/t4scan](https://github.com/YulinSec/t4scan) :  ![starts](https://img.shields.io/github/stars/YulinSec/t4scan.svg) ![forks](https://img.shields.io/github/forks/YulinSec/t4scan.svg)


## CVE-2022-30929
 Mini-Tmall v1.0 is vulnerable to Insecure Permissions via tomcat-embed-jasper.

- [https://github.com/nanaao/CVE-2022-30929](https://github.com/nanaao/CVE-2022-30929) :  ![starts](https://img.shields.io/github/stars/nanaao/CVE-2022-30929.svg) ![forks](https://img.shields.io/github/forks/nanaao/CVE-2022-30929.svg)


## CVE-2022-3236
 A code injection vulnerability in the User Portal and Webadmin allows a remote attacker to execute code in Sophos Firewall version v19.0 MR1 and older.

- [https://github.com/sml1nk/CVE-2022-3236-RCE](https://github.com/sml1nk/CVE-2022-3236-RCE) :  ![starts](https://img.shields.io/github/stars/sml1nk/CVE-2022-3236-RCE.svg) ![forks](https://img.shields.io/github/forks/sml1nk/CVE-2022-3236-RCE.svg)


## CVE-2022-2639
 An integer coercion error was found in the openvswitch kernel module. Given a sufficiently large number of actions, while copying and reserving memory for a new action of a new flow, the reserve_sfa_size() function does not return -EMSGSIZE as expected, potentially leading to an out-of-bounds write access. This flaw allows a local user to crash or potentially escalate their privileges on the system.

- [https://github.com/avboy1337/CVE-2022-2639-PipeVersion](https://github.com/avboy1337/CVE-2022-2639-PipeVersion) :  ![starts](https://img.shields.io/github/stars/avboy1337/CVE-2022-2639-PipeVersion.svg) ![forks](https://img.shields.io/github/forks/avboy1337/CVE-2022-2639-PipeVersion.svg)


## CVE-2022-0739
 The BookingPress WordPress plugin before 1.0.11 fails to properly sanitize user supplied POST data before it is used in a dynamically constructed SQL query via the bookingpress_front_get_category_services AJAX action (available to unauthenticated users), leading to an unauthenticated SQL Injection

- [https://github.com/destr4ct/CVE-2022-0739](https://github.com/destr4ct/CVE-2022-0739) :  ![starts](https://img.shields.io/github/stars/destr4ct/CVE-2022-0739.svg) ![forks](https://img.shields.io/github/forks/destr4ct/CVE-2022-0739.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/Mo0ns/Grafana_POC-CVE-2021-43798](https://github.com/Mo0ns/Grafana_POC-CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/Mo0ns/Grafana_POC-CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/Mo0ns/Grafana_POC-CVE-2021-43798.svg)


## CVE-2021-40154
 NXP LPC55S69 devices before A3 have a buffer over-read via a crafted wlength value in a GET Descriptor Configuration request during use of USB In-System Programming (ISP) mode. This discloses protected flash memory.

- [https://github.com/Jeromeyoung/CVE-2021-40154](https://github.com/Jeromeyoung/CVE-2021-40154) :  ![starts](https://img.shields.io/github/stars/Jeromeyoung/CVE-2021-40154.svg) ![forks](https://img.shields.io/github/forks/Jeromeyoung/CVE-2021-40154.svg)


## CVE-2018-14847
 MikroTik RouterOS through 6.42 allows unauthenticated remote attackers to read arbitrary files and remote authenticated attackers to write arbitrary files due to a directory traversal vulnerability in the WinBox interface.

- [https://github.com/babyshen/routeros-CVE-2018-14847-bytheway](https://github.com/babyshen/routeros-CVE-2018-14847-bytheway) :  ![starts](https://img.shields.io/github/stars/babyshen/routeros-CVE-2018-14847-bytheway.svg) ![forks](https://img.shields.io/github/forks/babyshen/routeros-CVE-2018-14847-bytheway.svg)

