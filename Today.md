# Update 2021-11-15
## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/kubota/POC-CVE-2021-41773](https://github.com/kubota/POC-CVE-2021-41773) :  ![starts](https://img.shields.io/github/stars/kubota/POC-CVE-2021-41773.svg) ![forks](https://img.shields.io/github/forks/kubota/POC-CVE-2021-41773.svg)


## CVE-2020-24030
 ForLogic Qualiex v1 and v3 has weak token expiration. This allows remote unauthenticated privilege escalation and access to sensitive data via token reuse.

- [https://github.com/redteambrasil/CVE-2020-24030](https://github.com/redteambrasil/CVE-2020-24030) :  ![starts](https://img.shields.io/github/stars/redteambrasil/CVE-2020-24030.svg) ![forks](https://img.shields.io/github/forks/redteambrasil/CVE-2020-24030.svg)


## CVE-2020-24029
 Because of unauthenticated password changes in ForLogic Qualiex v1 and v3, customer and admin permissions and data can be accessed via a simple request.

- [https://github.com/redteambrasil/CVE-2020-24029](https://github.com/redteambrasil/CVE-2020-24029) :  ![starts](https://img.shields.io/github/stars/redteambrasil/CVE-2020-24029.svg) ![forks](https://img.shields.io/github/forks/redteambrasil/CVE-2020-24029.svg)


## CVE-2020-24028
 ForLogic Qualiex v1 and v3 allows any authenticated customer to achieve privilege escalation via user creations, password changes, or user permission updates.

- [https://github.com/redteambrasil/CVE-2020-24028](https://github.com/redteambrasil/CVE-2020-24028) :  ![starts](https://img.shields.io/github/stars/redteambrasil/CVE-2020-24028.svg) ![forks](https://img.shields.io/github/forks/redteambrasil/CVE-2020-24028.svg)


## CVE-2019-19550
 Remote Authentication Bypass in Senior Rubiweb 6.2.34.28 and 6.2.34.37 allows admin access to sensitive information of affected users using vulnerable versions. The attacker only needs to provide the correct URL.

- [https://github.com/redteambrasil/CVE-2019-19550](https://github.com/redteambrasil/CVE-2019-19550) :  ![starts](https://img.shields.io/github/stars/redteambrasil/CVE-2019-19550.svg) ![forks](https://img.shields.io/github/forks/redteambrasil/CVE-2019-19550.svg)


## CVE-2019-18371
 An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. There is a directory traversal vulnerability to read arbitrary files via a misconfigured NGINX alias, as demonstrated by api-third-party/download/extdisks../etc/config/account. With this vulnerability, the attacker can bypass authentication.

- [https://github.com/AjayMT6/UltramanGaia](https://github.com/AjayMT6/UltramanGaia) :  ![starts](https://img.shields.io/github/stars/AjayMT6/UltramanGaia.svg) ![forks](https://img.shields.io/github/forks/AjayMT6/UltramanGaia.svg)


## CVE-2019-18370
 An issue was discovered on Xiaomi Mi WiFi R3G devices before 2.28.23-stable. The backup file is in tar.gz format. After uploading, the application uses the tar zxf command to decompress, so one can control the contents of the files in the decompressed directory. In addition, the application's sh script for testing upload and download speeds reads a URL list from /tmp/speedtest_urls.xml, and there is a command injection vulnerability, as demonstrated by api/xqnetdetect/netspeed.

- [https://github.com/AjayMT6/UltramanGaia](https://github.com/AjayMT6/UltramanGaia) :  ![starts](https://img.shields.io/github/stars/AjayMT6/UltramanGaia.svg) ![forks](https://img.shields.io/github/forks/AjayMT6/UltramanGaia.svg)


## CVE-2017-17562
 Embedthis GoAhead before 3.6.5 allows remote code execution if CGI is enabled and a CGI program is dynamically linked. This is a result of initializing the environment of forked CGI scripts using untrusted HTTP request parameters in the cgiHandler function in cgi.c. When combined with the glibc dynamic linker, this behaviour can be abused for remote code execution using special parameter names such as LD_PRELOAD. An attacker can POST their shared object payload in the body of the request, and reference it using /proc/self/fd/0.

- [https://github.com/fssecur3/goahead-rce-exploit](https://github.com/fssecur3/goahead-rce-exploit) :  ![starts](https://img.shields.io/github/stars/fssecur3/goahead-rce-exploit.svg) ![forks](https://img.shields.io/github/forks/fssecur3/goahead-rce-exploit.svg)

