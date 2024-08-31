# Update 2024-08-31
## CVE-2024-25641
 Cacti provides an operational monitoring and fault management framework. Prior to version 1.2.27, an arbitrary file write vulnerability, exploitable through the &quot;Package Import&quot; feature, allows authenticated users having the &quot;Import Templates&quot; permission to execute arbitrary PHP code on the web server. The vulnerability is located within the `import_package()` function defined into the `/lib/import.php` script. The function blindly trusts the filename and file content provided within the XML data, and writes such files into the Cacti base path (or even outside, since path traversal sequences are not filtered). This can be exploited to write or overwrite arbitrary files on the web server, leading to execution of arbitrary PHP code or other security impacts. Version 1.2.27 contains a patch for this issue.

- [https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26](https://github.com/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26) :  ![starts](https://img.shields.io/github/stars/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26.svg) ![forks](https://img.shields.io/github/forks/StopThatTalace/CVE-2024-25641-CACTI-RCE-1.2.26.svg)


## CVE-2024-24919
 Potentially allowing an attacker to read certain information on Check Point Security Gateways once connected to the internet and enabled with remote Access VPN or Mobile Access Software Blades. A Security fix that mitigates this vulnerability is available.

- [https://github.com/LuisMateo1/Arbitrary-File-Read-CVE-2024-24919](https://github.com/LuisMateo1/Arbitrary-File-Read-CVE-2024-24919) :  ![starts](https://img.shields.io/github/stars/LuisMateo1/Arbitrary-File-Read-CVE-2024-24919.svg) ![forks](https://img.shields.io/github/forks/LuisMateo1/Arbitrary-File-Read-CVE-2024-24919.svg)


## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/JAthulya/CVE-2024-23897](https://github.com/JAthulya/CVE-2024-23897) :  ![starts](https://img.shields.io/github/stars/JAthulya/CVE-2024-23897.svg) ![forks](https://img.shields.io/github/forks/JAthulya/CVE-2024-23897.svg)


## CVE-2024-5274
 Type Confusion in V8 in Google Chrome prior to 125.0.6422.112 allowed a remote attacker to execute arbitrary code inside a sandbox via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/mistymntncop/CVE-2024-5274](https://github.com/mistymntncop/CVE-2024-5274) :  ![starts](https://img.shields.io/github/stars/mistymntncop/CVE-2024-5274.svg) ![forks](https://img.shields.io/github/forks/mistymntncop/CVE-2024-5274.svg)


## CVE-2024-4516
 A vulnerability was found in Campcodes Complete Web-Based School Management System 1.0 and classified as problematic. Affected by this issue is some unknown functionality of the file /view/timetable.php. The manipulation of the argument grade leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-263120.

- [https://github.com/0romos/CVE-2024-45163](https://github.com/0romos/CVE-2024-45163) :  ![starts](https://img.shields.io/github/stars/0romos/CVE-2024-45163.svg) ![forks](https://img.shields.io/github/forks/0romos/CVE-2024-45163.svg)


## CVE-2024-4304
 A Cross-Site Scripting XSS vulnerability has been detected on GT3 Soluciones SWAL. This vulnerability consists in a reflected XSS in the Titular parameter inside Gestion 'Documental &gt; Seguimiento de Expedientes &gt; Alta de Expedientes'.

- [https://github.com/convisolabs/CVE-2024-43044-jenkins](https://github.com/convisolabs/CVE-2024-43044-jenkins) :  ![starts](https://img.shields.io/github/stars/convisolabs/CVE-2024-43044-jenkins.svg) ![forks](https://img.shields.io/github/forks/convisolabs/CVE-2024-43044-jenkins.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/te5t321/Spring4Shell-CVE-2022-22965.py](https://github.com/te5t321/Spring4Shell-CVE-2022-22965.py) :  ![starts](https://img.shields.io/github/stars/te5t321/Spring4Shell-CVE-2022-22965.py.svg) ![forks](https://img.shields.io/github/forks/te5t321/Spring4Shell-CVE-2022-22965.py.svg)


## CVE-2021-34473
 Microsoft Exchange Server Remote Code Execution Vulnerability

- [https://github.com/learningsurface/ProxyShell-CVE-2021-34473.py](https://github.com/learningsurface/ProxyShell-CVE-2021-34473.py) :  ![starts](https://img.shields.io/github/stars/learningsurface/ProxyShell-CVE-2021-34473.py.svg) ![forks](https://img.shields.io/github/forks/learningsurface/ProxyShell-CVE-2021-34473.py.svg)


## CVE-2019-15107
 An issue was discovered in Webmin &lt;=1.920. The parameter old in password_change.cgi contains a command injection vulnerability.

- [https://github.com/NasrallahBaadi/CVE-2019-15107](https://github.com/NasrallahBaadi/CVE-2019-15107) :  ![starts](https://img.shields.io/github/stars/NasrallahBaadi/CVE-2019-15107.svg) ![forks](https://img.shields.io/github/forks/NasrallahBaadi/CVE-2019-15107.svg)


## CVE-2019-9168
 WooCommerce before 3.5.5 allows XSS via a Photoswipe caption.

- [https://github.com/flouciel/WooCommerce-CVEs](https://github.com/flouciel/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/flouciel/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/flouciel/WooCommerce-CVEs.svg)


## CVE-2018-20148
 In WordPress before 4.9.9 and 5.x before 5.0.1, contributors could conduct PHP object injection attacks via crafted metadata in a wp.getMediaItem XMLRPC call. This is caused by mishandling of serialized data at phar:// URLs in the wp_get_attachment_thumb_file function in wp-includes/post.php.

- [https://github.com/flouciel/WooCommerce-CVEs](https://github.com/flouciel/WooCommerce-CVEs) :  ![starts](https://img.shields.io/github/stars/flouciel/WooCommerce-CVEs.svg) ![forks](https://img.shields.io/github/forks/flouciel/WooCommerce-CVEs.svg)

