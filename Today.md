# Update 2022-07-12
## CVE-2022-33980
 Apache Commons Configuration performs variable interpolation, allowing properties to be dynamically evaluated and expanded. The standard format for interpolation is &quot;${prefix:name}&quot;, where &quot;prefix&quot; is used to locate an instance of org.apache.commons.configuration2.interpol.Lookup that performs the interpolation. Starting with version 2.4 and continuing through 2.7, the set of default Lookup instances included interpolators that could result in arbitrary code execution or contact with remote servers. These lookups are: - &quot;script&quot; - execute expressions using the JVM script execution engine (javax.script) - &quot;dns&quot; - resolve dns records - &quot;url&quot; - load values from urls, including from remote servers Applications using the interpolation defaults in the affected versions may be vulnerable to remote code execution or unintentional contact with remote servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons Configuration 2.8.0, which disables the problematic interpolators by default.

- [https://github.com/trhacknon/CVE-2022-33980-Apache-Commons-Configuration-RCE](https://github.com/trhacknon/CVE-2022-33980-Apache-Commons-Configuration-RCE) :  ![starts](https://img.shields.io/github/stars/trhacknon/CVE-2022-33980-Apache-Commons-Configuration-RCE.svg) ![forks](https://img.shields.io/github/forks/trhacknon/CVE-2022-33980-Apache-Commons-Configuration-RCE.svg)


## CVE-2021-35042
 Django 3.1.x before 3.1.13 and 3.2.x before 3.2.5 allows QuerySet.order_by SQL injection if order_by is untrusted input from a client of a web application.

- [https://github.com/r4vi/CVE-2021-35042](https://github.com/r4vi/CVE-2021-35042) :  ![starts](https://img.shields.io/github/stars/r4vi/CVE-2021-35042.svg) ![forks](https://img.shields.io/github/forks/r4vi/CVE-2021-35042.svg)


## CVE-2021-31805
 The fix issued for CVE-2020-17530 was incomplete. So from Apache Struts 2.0.0 to 2.5.29, still some of the tag&#8217;s attributes could perform a double evaluation if a developer applied forced OGNL evaluation by using the %{...} syntax. Using forced OGNL evaluation on untrusted user input can lead to a Remote Code Execution and security degradation.

- [https://github.com/z92g/CVE-2021-31805](https://github.com/z92g/CVE-2021-31805) :  ![starts](https://img.shields.io/github/stars/z92g/CVE-2021-31805.svg) ![forks](https://img.shields.io/github/forks/z92g/CVE-2021-31805.svg)


## CVE-2021-31166
 HTTP Protocol Stack Remote Code Execution Vulnerability

- [https://github.com/imiko0u0/CVE-2021-31166-exploit](https://github.com/imiko0u0/CVE-2021-31166-exploit) :  ![starts](https://img.shields.io/github/stars/imiko0u0/CVE-2021-31166-exploit.svg) ![forks](https://img.shields.io/github/forks/imiko0u0/CVE-2021-31166-exploit.svg)


## CVE-2021-25094
 The Tatsu WordPress plugin before 3.3.12 add_custom_font action can be used without prior authentication to upload a rogue zip file which is uncompressed under the WordPress's upload directory. By adding a PHP shell with a filename starting with a dot &quot;.&quot;, this can bypass extension control implemented in the plugin. Moreover, there is a race condition in the zip extraction process which makes the shell file live long enough on the filesystem to be callable by an attacker.

- [https://github.com/xdx57/CVE-2021-25094](https://github.com/xdx57/CVE-2021-25094) :  ![starts](https://img.shields.io/github/stars/xdx57/CVE-2021-25094.svg) ![forks](https://img.shields.io/github/forks/xdx57/CVE-2021-25094.svg)


## CVE-2020-6286
 The insufficient input path validation of certain parameter in the web service of SAP NetWeaver AS JAVA (LM Configuration Wizard), versions - 7.30, 7.31, 7.40, 7.50, allows an unauthenticated attacker to exploit a method to download zip files to a specific directory, leading to Path Traversal.

- [https://github.com/duc-nt/CVE-2020-6287-exploit](https://github.com/duc-nt/CVE-2020-6287-exploit) :  ![starts](https://img.shields.io/github/stars/duc-nt/CVE-2020-6287-exploit.svg) ![forks](https://img.shields.io/github/forks/duc-nt/CVE-2020-6287-exploit.svg)


## CVE-2020-5510
 PHPGurukul Hostel Management System v2.0 allows SQL injection via the id parameter in the full-profile.php file.

- [https://github.com/5l1v3r1/CVE-2020-5510](https://github.com/5l1v3r1/CVE-2020-5510) :  ![starts](https://img.shields.io/github/stars/5l1v3r1/CVE-2020-5510.svg) ![forks](https://img.shields.io/github/forks/5l1v3r1/CVE-2020-5510.svg)

