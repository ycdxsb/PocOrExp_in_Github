# Update 2025-08-31
## CVE-2025-57819
 FreePBX is an open-source web-based graphical user interface. FreePBX 15, 16, and 17 endpoints are vulnerable due to insufficiently sanitized user-supplied data allowing unauthenticated access to FreePBX Administrator leading to arbitrary database manipulation and remote code execution. This issue has been patched in endpoint versions 15.0.66, 16.0.89, and 17.0.3.

- [https://github.com/rxerium/CVE-2025-57819](https://github.com/rxerium/CVE-2025-57819) :  ![starts](https://img.shields.io/github/stars/rxerium/CVE-2025-57819.svg) ![forks](https://img.shields.io/github/forks/rxerium/CVE-2025-57819.svg)
- [https://github.com/Sucuri-Labs/CVE-2025-57819-ioc-check](https://github.com/Sucuri-Labs/CVE-2025-57819-ioc-check) :  ![starts](https://img.shields.io/github/stars/Sucuri-Labs/CVE-2025-57819-ioc-check.svg) ![forks](https://img.shields.io/github/forks/Sucuri-Labs/CVE-2025-57819-ioc-check.svg)


## CVE-2025-55763
 Buffer Overflow in the URI parser of CivetWeb 1.14 through 1.16 (latest) allows a remote attacker to achieve remote code execution via a crafted HTTP request. This vulnerability is triggered during request processing and may allow an attacker to corrupt heap memory, potentially leading to denial of service or arbitrary code execution.

- [https://github.com/krispybyte/CVE-2025-55763](https://github.com/krispybyte/CVE-2025-55763) :  ![starts](https://img.shields.io/github/stars/krispybyte/CVE-2025-55763.svg) ![forks](https://img.shields.io/github/forks/krispybyte/CVE-2025-55763.svg)


## CVE-2025-55580
 SolidInvoice 2.3.7 and v.2.3.8 is vulnerable to Cross Site Scripting (XSS) in the client's functionality.

- [https://github.com/ddobrev25/CVE-2025-55580](https://github.com/ddobrev25/CVE-2025-55580) :  ![starts](https://img.shields.io/github/stars/ddobrev25/CVE-2025-55580.svg) ![forks](https://img.shields.io/github/forks/ddobrev25/CVE-2025-55580.svg)


## CVE-2025-55579
 SolidInvoice 2.3.7 and fixed in v.2.3.8 is vulnerable to Cross Site Scripting (XSS) in the Tax Rate functionality.

- [https://github.com/ddobrev25/CVE-2025-55579](https://github.com/ddobrev25/CVE-2025-55579) :  ![starts](https://img.shields.io/github/stars/ddobrev25/CVE-2025-55579.svg) ![forks](https://img.shields.io/github/forks/ddobrev25/CVE-2025-55579.svg)


## CVE-2025-55188
 7-Zip before 25.01 does not always properly handle symbolic links during extraction.

- [https://github.com/lunbun/CVE-2025-55188](https://github.com/lunbun/CVE-2025-55188) :  ![starts](https://img.shields.io/github/stars/lunbun/CVE-2025-55188.svg) ![forks](https://img.shields.io/github/forks/lunbun/CVE-2025-55188.svg)


## CVE-2025-54309
 CrushFTP 10 before 10.8.5 and 11 before 11.3.4_23, when the DMZ proxy feature is not used, mishandles AS2 validation and consequently allows remote attackers to obtain admin access via HTTPS, as exploited in the wild in July 2025.

- [https://github.com/blueisbeautiful/CVE-2025-54309](https://github.com/blueisbeautiful/CVE-2025-54309) :  ![starts](https://img.shields.io/github/stars/blueisbeautiful/CVE-2025-54309.svg) ![forks](https://img.shields.io/github/forks/blueisbeautiful/CVE-2025-54309.svg)


## CVE-2025-49113
 Roundcube Webmail before 1.5.10 and 1.6.x before 1.6.11 allows remote code execution by authenticated users because the _from parameter in a URL is not validated in program/actions/settings/upload.php, leading to PHP Object Deserialization.

- [https://github.com/AC8999/CVE-2025-49113](https://github.com/AC8999/CVE-2025-49113) :  ![starts](https://img.shields.io/github/stars/AC8999/CVE-2025-49113.svg) ![forks](https://img.shields.io/github/forks/AC8999/CVE-2025-49113.svg)


## CVE-2025-48384
 Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When reading a config value, Git strips any trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted, causing the CR to be lost when the config is later read. When initializing a submodule, if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location. If a symlink exists that points the altered path to the submodule hooks directory, and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout. This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.

- [https://github.com/arun1033/CVE-2025-48384](https://github.com/arun1033/CVE-2025-48384) :  ![starts](https://img.shields.io/github/stars/arun1033/CVE-2025-48384.svg) ![forks](https://img.shields.io/github/forks/arun1033/CVE-2025-48384.svg)


## CVE-2025-34040
 An arbitrary file upload vulnerability exists in the Zhiyuan OA platform 5.0, 5.1 - 5.6sp1, 6.0 - 6.1sp2, 7.0, 7.0sp1 - 7.1, 7.1sp1, and 8.0 - 8.0sp2 via the wpsAssistServlet interface. The realFileType and fileId parameters are improperly validated during multipart file uploads, allowing unauthenticated attackers to upload crafted JSP files outside of intended directories using path traversal. Successful exploitation enables remote code execution as the uploaded file can be accessed and executed through the web server.

- [https://github.com/jisi-001/CVE-2025-34040Exp](https://github.com/jisi-001/CVE-2025-34040Exp) :  ![starts](https://img.shields.io/github/stars/jisi-001/CVE-2025-34040Exp.svg) ![forks](https://img.shields.io/github/forks/jisi-001/CVE-2025-34040Exp.svg)


## CVE-2025-5210
 A vulnerability has been found in PHPGurukul Employee Record Management System 1.3 and classified as critical. This vulnerability affects unknown code of the file /loginerms.php. The manipulation of the argument Email leads to sql injection. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used.

- [https://github.com/changyaoyou/CVE-2025-52100](https://github.com/changyaoyou/CVE-2025-52100) :  ![starts](https://img.shields.io/github/stars/changyaoyou/CVE-2025-52100.svg) ![forks](https://img.shields.io/github/forks/changyaoyou/CVE-2025-52100.svg)


## CVE-2025-0309
 An insufficient validation on the server connection endpoint in Netskope Client allows local users to elevate privileges on the system. The insufficient validation allows Netskope Client to connect to any other server with Public Signed CA TLS certificates and send specially crafted responses to elevate privileges.

- [https://github.com/AmberWolfCyber/UpSkope](https://github.com/AmberWolfCyber/UpSkope) :  ![starts](https://img.shields.io/github/stars/AmberWolfCyber/UpSkope.svg) ![forks](https://img.shields.io/github/forks/AmberWolfCyber/UpSkope.svg)


## CVE-2023-44487
 The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023.

- [https://github.com/gmh5225/CVE_2023_44487-Rapid_Reset](https://github.com/gmh5225/CVE_2023_44487-Rapid_Reset) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE_2023_44487-Rapid_Reset.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE_2023_44487-Rapid_Reset.svg)


## CVE-2017-9841
 Util/PHP/eval-stdin.php in PHPUnit before 4.8.28 and 5.x before 5.6.3 allows remote attackers to execute arbitrary PHP code via HTTP POST data beginning with a "?php " substring, as demonstrated by an attack on a site with an exposed /vendor folder, i.e., external access to the /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php URI.

- [https://github.com/drcrypterdotru/PHPUnit-GoScan](https://github.com/drcrypterdotru/PHPUnit-GoScan) :  ![starts](https://img.shields.io/github/stars/drcrypterdotru/PHPUnit-GoScan.svg) ![forks](https://img.shields.io/github/forks/drcrypterdotru/PHPUnit-GoScan.svg)

