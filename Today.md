# Update 2024-12-10
## CVE-2024-23897
 Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.

- [https://github.com/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins](https://github.com/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins) :  ![starts](https://img.shields.io/github/stars/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins.svg) ![forks](https://img.shields.io/github/forks/D1se0/CVE-2024-23897-Vulnerabilidad-Jenkins.svg)


## CVE-2021-23017
 A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.

- [https://github.com/z3usx01/CVE-2021-23017-POC](https://github.com/z3usx01/CVE-2021-23017-POC) :  ![starts](https://img.shields.io/github/stars/z3usx01/CVE-2021-23017-POC.svg) ![forks](https://img.shields.io/github/forks/z3usx01/CVE-2021-23017-POC.svg)


## CVE-2019-8943
 WordPress through 5.0.3 allows Path Traversal in wp_crop_image(). An attacker (who has privileges to crop an image) can write the output image to an arbitrary directory via a filename containing two image extensions and ../ sequences, such as a filename ending with the .jpg?/../../file.jpg substring.

- [https://github.com/oussama-rahali/CVE-2019-8943](https://github.com/oussama-rahali/CVE-2019-8943) :  ![starts](https://img.shields.io/github/stars/oussama-rahali/CVE-2019-8943.svg) ![forks](https://img.shields.io/github/forks/oussama-rahali/CVE-2019-8943.svg)


## CVE-2019-8942
 WordPress before 4.9.9 and 5.x before 5.0.1 allows remote code execution because an _wp_attached_file Post Meta entry can be changed to an arbitrary string, such as one ending with a .jpg?file.php substring. An attacker with author privileges can execute arbitrary code by uploading a crafted image containing PHP code in the Exif metadata. Exploitation can leverage CVE-2019-8943.

- [https://github.com/oussama-rahali/CVE-2019-8943](https://github.com/oussama-rahali/CVE-2019-8943) :  ![starts](https://img.shields.io/github/stars/oussama-rahali/CVE-2019-8943.svg) ![forks](https://img.shields.io/github/forks/oussama-rahali/CVE-2019-8943.svg)


## CVE-2017-5638
 The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.32 and 2.5.x before 2.5.10.1 has incorrect exception handling and error-message generation during file-upload attempts, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header, as exploited in the wild in March 2017 with a Content-Type header containing a #cmd= string.

- [https://github.com/Xernary/CVE-2017-5638-POC](https://github.com/Xernary/CVE-2017-5638-POC) :  ![starts](https://img.shields.io/github/stars/Xernary/CVE-2017-5638-POC.svg) ![forks](https://img.shields.io/github/forks/Xernary/CVE-2017-5638-POC.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/Jimmy01240397/CVE-2012-1823-Analyze](https://github.com/Jimmy01240397/CVE-2012-1823-Analyze) :  ![starts](https://img.shields.io/github/stars/Jimmy01240397/CVE-2012-1823-Analyze.svg) ![forks](https://img.shields.io/github/forks/Jimmy01240397/CVE-2012-1823-Analyze.svg)


## CVE-2004-1561
 Buffer overflow in Icecast 2.0.1 and earlier allows remote attackers to execute arbitrary code via an HTTP request with a large number of headers.

- [https://github.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-](https://github.com/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-) :  ![starts](https://img.shields.io/github/stars/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-.svg) ![forks](https://img.shields.io/github/forks/Danyw24/CVE-2004-1561-Icecast-Header-Overwrite-buffer-overflow-RCE-2.0.1-Win32-.svg)

