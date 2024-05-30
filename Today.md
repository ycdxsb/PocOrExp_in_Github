# Update 2024-05-30
## CVE-2024-36079
 An issue was discovered in Vaultize 21.07.27. When uploading files, there is no check that the filename parameter is correct. As a result, a temporary file will be created outside the specified directory when the file is downloaded. To exploit this, an authenticated user would upload a file with an incorrect file name, and then download it.

- [https://github.com/DxRvs/vaultize_CVE-2024-36079](https://github.com/DxRvs/vaultize_CVE-2024-36079) :  ![starts](https://img.shields.io/github/stars/DxRvs/vaultize_CVE-2024-36079.svg) ![forks](https://img.shields.io/github/forks/DxRvs/vaultize_CVE-2024-36079.svg)


## CVE-2024-35511
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/efekaanakkar/CVE-2024-35511](https://github.com/efekaanakkar/CVE-2024-35511) :  ![starts](https://img.shields.io/github/stars/efekaanakkar/CVE-2024-35511.svg) ![forks](https://img.shields.io/github/forks/efekaanakkar/CVE-2024-35511.svg)


## CVE-2024-35475
 A Cross-Site Request Forgery (CSRF) vulnerability was discovered in OpenKM Community Edition on or before version 6.3.12. The vulnerability exists in /admin/DatabaseQuery, which allows an attacker to manipulate a victim with administrative privileges to execute arbitrary SQL commands.

- [https://github.com/carsonchan12345/CVE-2024-35475](https://github.com/carsonchan12345/CVE-2024-35475) :  ![starts](https://img.shields.io/github/stars/carsonchan12345/CVE-2024-35475.svg) ![forks](https://img.shields.io/github/forks/carsonchan12345/CVE-2024-35475.svg)


## CVE-2024-35333
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/momo1239/CVE-2024-35333](https://github.com/momo1239/CVE-2024-35333) :  ![starts](https://img.shields.io/github/stars/momo1239/CVE-2024-35333.svg) ![forks](https://img.shields.io/github/forks/momo1239/CVE-2024-35333.svg)


## CVE-2024-34958
 idccms v1.35 was discovered to contain a Cross-Site Request Forgery (CSRF) via the component admin/banner_deal.php?mudi=add

- [https://github.com/Gr-1m/CVE-2024-34958-1](https://github.com/Gr-1m/CVE-2024-34958-1) :  ![starts](https://img.shields.io/github/stars/Gr-1m/CVE-2024-34958-1.svg) ![forks](https://img.shields.io/github/forks/Gr-1m/CVE-2024-34958-1.svg)


## CVE-2024-34716
 PrestaShop is an open source e-commerce web application. A cross-site scripting (XSS) vulnerability that only affects PrestaShops with customer-thread feature flag enabled is present starting from PrestaShop 8.1.0 and prior to PrestaShop 8.1.6. When the customer thread feature flag is enabled through the front-office contact form, a hacker can upload a malicious file containing an XSS that will be executed when an admin opens the attached file in back office. The script injected can access the session and the security token, which allows it to perform any authenticated action in the scope of the administrator's right. This vulnerability is patched in 8.1.6. A workaround is to disable the customer-thread feature-flag.

- [https://github.com/aelmokhtar/CVE-2024-34716_PoC](https://github.com/aelmokhtar/CVE-2024-34716_PoC) :  ![starts](https://img.shields.io/github/stars/aelmokhtar/CVE-2024-34716_PoC.svg) ![forks](https://img.shields.io/github/forks/aelmokhtar/CVE-2024-34716_PoC.svg)


## CVE-2024-34582
 Sunhillo SureLine through 8.10.0 on RICI 5000 devices allows cgi/usrPasswd.cgi userid_change XSS within the Forgot Password feature.

- [https://github.com/silent6trinity/CVE-2024-34582](https://github.com/silent6trinity/CVE-2024-34582) :  ![starts](https://img.shields.io/github/stars/silent6trinity/CVE-2024-34582.svg) ![forks](https://img.shields.io/github/forks/silent6trinity/CVE-2024-34582.svg)


## CVE-2024-34474
 Clario through 2024-04-11 for Desktop has weak permissions for %PROGRAMDATA%\Clario and tries to load DLLs from there as SYSTEM.

- [https://github.com/Alaatk/CVE-2024-34474](https://github.com/Alaatk/CVE-2024-34474) :  ![starts](https://img.shields.io/github/stars/Alaatk/CVE-2024-34474.svg) ![forks](https://img.shields.io/github/forks/Alaatk/CVE-2024-34474.svg)


## CVE-2024-34472
 An issue was discovered in HSC Mailinspector 5.2.17-3 through v.5.2.18. An authenticated blind SQL injection vulnerability exists in the mliRealtimeEmails.php file. The ordemGrid parameter in a POST request to /mailinspector/mliRealtimeEmails.php does not properly sanitize input, allowing an authenticated attacker to execute arbitrary SQL commands, leading to the potential disclosure of the entire application database.

- [https://github.com/osvaldotenorio/CVE-2024-34472](https://github.com/osvaldotenorio/CVE-2024-34472) :  ![starts](https://img.shields.io/github/stars/osvaldotenorio/CVE-2024-34472.svg) ![forks](https://img.shields.io/github/forks/osvaldotenorio/CVE-2024-34472.svg)


## CVE-2024-34471
 An issue was discovered in HSC Mailinspector 5.2.17-3. A Path Traversal vulnerability (resulting in file deletion) exists in the mliRealtimeEmails.php file. The filename parameter in the export HTML functionality does not properly validate the file location, allowing an attacker to read and delete arbitrary files on the server. This was observed when the mliRealtimeEmails.php file itself was read and subsequently deleted, resulting in a 404 error for the file and disruption of email information loading.

- [https://github.com/osvaldotenorio/CVE-2024-34471](https://github.com/osvaldotenorio/CVE-2024-34471) :  ![starts](https://img.shields.io/github/stars/osvaldotenorio/CVE-2024-34471.svg) ![forks](https://img.shields.io/github/forks/osvaldotenorio/CVE-2024-34471.svg)


## CVE-2024-34470
 An issue was discovered in HSC Mailinspector 5.2.17-3 through v.5.2.18. An Unauthenticated Path Traversal vulnerability exists in the /public/loader.php file. The path parameter does not properly filter whether the file and directory passed are part of the webroot, allowing an attacker to read arbitrary files on the server.

- [https://github.com/osvaldotenorio/CVE-2024-34470](https://github.com/osvaldotenorio/CVE-2024-34470) :  ![starts](https://img.shields.io/github/stars/osvaldotenorio/CVE-2024-34470.svg) ![forks](https://img.shields.io/github/forks/osvaldotenorio/CVE-2024-34470.svg)


## CVE-2024-34469
 Rukovoditel before 3.5.3 allows XSS via user_photo to index.php?module=users/registration&amp;action=save.

- [https://github.com/Toxich4/CVE-2024-34469](https://github.com/Toxich4/CVE-2024-34469) :  ![starts](https://img.shields.io/github/stars/Toxich4/CVE-2024-34469.svg) ![forks](https://img.shields.io/github/forks/Toxich4/CVE-2024-34469.svg)


## CVE-2024-34351
 Next.js is a React framework that can provide building blocks to create web applications. A Server-Side Request Forgery (SSRF) vulnerability was identified in Next.js Server Actions. If the `Host` header is modified, and the below conditions are also met, an attacker may be able to make requests that appear to be originating from the Next.js application server itself. The required conditions are 1) Next.js is running in a self-hosted manner; 2) the Next.js application makes use of Server Actions; and 3) the Server Action performs a redirect to a relative path which starts with a `/`. This vulnerability was fixed in Next.js `14.1.1`.

- [https://github.com/Voorivex/CVE-2024-34351](https://github.com/Voorivex/CVE-2024-34351) :  ![starts](https://img.shields.io/github/stars/Voorivex/CVE-2024-34351.svg) ![forks](https://img.shields.io/github/forks/Voorivex/CVE-2024-34351.svg)


## CVE-2024-34342
 react-pdf displays PDFs in React apps. If PDF.js is used to load a malicious PDF, and PDF.js is configured with `isEvalSupported` set to `true` (which is the default value), unrestricted attacker-controlled JavaScript will be executed in the context of the hosting domain. This vulnerability is fixed in 7.7.3 and 8.0.2.

- [https://github.com/LOURC0D3/CVE-2024-4367-PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC) :  ![starts](https://img.shields.io/github/stars/LOURC0D3/CVE-2024-4367-PoC.svg) ![forks](https://img.shields.io/github/forks/LOURC0D3/CVE-2024-4367-PoC.svg)


## CVE-2024-34310
 Jin Fang Times Content Management System v3.2.3 was discovered to contain a SQL injection vulnerability via the id parameter.

- [https://github.com/3309899621/CVE-2024-34310](https://github.com/3309899621/CVE-2024-34310) :  ![starts](https://img.shields.io/github/stars/3309899621/CVE-2024-34310.svg) ![forks](https://img.shields.io/github/forks/3309899621/CVE-2024-34310.svg)


## CVE-2024-34226
 SQL injection vulnerability in /php-sqlite-vms/?page=manage_visitor&amp;id=1 in SourceCodester Visitor Management System 1.0 allow attackers to execute arbitrary SQL commands via the id parameters.

- [https://github.com/dovankha/CVE-2024-34226](https://github.com/dovankha/CVE-2024-34226) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34226.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34226.svg)


## CVE-2024-34225
 Cross Site Scripting vulnerability in php-lms/admin/?page=system_info in Computer Laboratory Management System using PHP and MySQL 1.0 allow remote attackers to inject arbitrary web script or HTML via the name, shortname parameters.

- [https://github.com/dovankha/CVE-2024-34225](https://github.com/dovankha/CVE-2024-34225) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34225.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34225.svg)


## CVE-2024-34224
 Cross Site Scripting vulnerability in /php-lms/classes/Users.php?f=save in Computer Laboratory Management System using PHP and MySQL 1.0 allow remote attackers to inject arbitrary web script or HTML via the firstname, middlename, lastname parameters.

- [https://github.com/dovankha/CVE-2024-34224](https://github.com/dovankha/CVE-2024-34224) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34224.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34224.svg)


## CVE-2024-34223
 Insecure permission vulnerability in /hrm/leaverequest.php in SourceCodester Human Resource Management System 1.0 allow attackers to approve or reject leave ticket.

- [https://github.com/dovankha/CVE-2024-34223](https://github.com/dovankha/CVE-2024-34223) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34223.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34223.svg)


## CVE-2024-34222
 Sourcecodester Human Resource Management System 1.0 is vulnerable to SQL Injection via the searccountry parameter.

- [https://github.com/dovankha/CVE-2024-34222](https://github.com/dovankha/CVE-2024-34222) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34222.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34222.svg)


## CVE-2024-34221
 Sourcecodester Human Resource Management System 1.0 is vulnerable to Insecure Permissions resulting in privilege escalation.

- [https://github.com/dovankha/CVE-2024-34221](https://github.com/dovankha/CVE-2024-34221) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34221.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34221.svg)


## CVE-2024-34220
 Sourcecodester Human Resource Management System 1.0 is vulnerable to SQL Injection via the 'leave' parameter.

- [https://github.com/dovankha/CVE-2024-34220](https://github.com/dovankha/CVE-2024-34220) :  ![starts](https://img.shields.io/github/stars/dovankha/CVE-2024-34220.svg) ![forks](https://img.shields.io/github/forks/dovankha/CVE-2024-34220.svg)


## CVE-2024-32002
 Git is a revision control system. Prior to versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4, repositories with submodules can be crafted in a way that exploits a bug in Git whereby it can be fooled into writing files not into the submodule's worktree but into a `.git/` directory. This allows writing a hook that will be executed while the clone operation is still running, giving the user no opportunity to inspect the code that is being executed. The problem has been patched in versions 2.45.1, 2.44.1, 2.43.4, 2.42.2, 2.41.1, 2.40.2, and 2.39.4. If symbolic link support is disabled in Git (e.g. via `git config --global core.symlinks false`), the described attack won't work. As always, it is best to avoid cloning repositories from untrusted sources.

- [https://github.com/Goplush/CVE-2024-32002-git-rce](https://github.com/Goplush/CVE-2024-32002-git-rce) :  ![starts](https://img.shields.io/github/stars/Goplush/CVE-2024-32002-git-rce.svg) ![forks](https://img.shields.io/github/forks/Goplush/CVE-2024-32002-git-rce.svg)


## CVE-2024-23108
 An improper neutralization of special elements used in an os command ('os command injection') in Fortinet FortiSIEM version 7.1.0 through 7.1.1 and 7.0.0 through 7.0.2 and 6.7.0 through 6.7.8 and 6.6.0 through 6.6.3 and 6.5.0 through 6.5.2 and 6.4.0 through 6.4.2 allows attacker to execute unauthorized code or commands via via crafted API requests.

- [https://github.com/horizon3ai/CVE-2024-23108](https://github.com/horizon3ai/CVE-2024-23108) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2024-23108.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2024-23108.svg)
- [https://github.com/hitem/CVE-2024-23108](https://github.com/hitem/CVE-2024-23108) :  ![starts](https://img.shields.io/github/stars/hitem/CVE-2024-23108.svg) ![forks](https://img.shields.io/github/forks/hitem/CVE-2024-23108.svg)


## CVE-2024-5084
 The Hash Form &#8211; Drag &amp; Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Chocapikk/CVE-2024-5084](https://github.com/Chocapikk/CVE-2024-5084) :  ![starts](https://img.shields.io/github/stars/Chocapikk/CVE-2024-5084.svg) ![forks](https://img.shields.io/github/forks/Chocapikk/CVE-2024-5084.svg)
- [https://github.com/KTN1990/CVE-2024-5084](https://github.com/KTN1990/CVE-2024-5084) :  ![starts](https://img.shields.io/github/stars/KTN1990/CVE-2024-5084.svg) ![forks](https://img.shields.io/github/forks/KTN1990/CVE-2024-5084.svg)


## CVE-2024-4956
 Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.

- [https://github.com/ifconfig-me/CVE-2024-4956-Bulk-Scanner](https://github.com/ifconfig-me/CVE-2024-4956-Bulk-Scanner) :  ![starts](https://img.shields.io/github/stars/ifconfig-me/CVE-2024-4956-Bulk-Scanner.svg) ![forks](https://img.shields.io/github/forks/ifconfig-me/CVE-2024-4956-Bulk-Scanner.svg)
- [https://github.com/xungzzz/CVE-2024-4956](https://github.com/xungzzz/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/xungzzz/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/xungzzz/CVE-2024-4956.svg)
- [https://github.com/TypicalModMaker/list-of-vulnerable-sonatype-servers](https://github.com/TypicalModMaker/list-of-vulnerable-sonatype-servers) :  ![starts](https://img.shields.io/github/stars/TypicalModMaker/list-of-vulnerable-sonatype-servers.svg) ![forks](https://img.shields.io/github/forks/TypicalModMaker/list-of-vulnerable-sonatype-servers.svg)
- [https://github.com/banditzCyber0x/CVE-2024-4956](https://github.com/banditzCyber0x/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/banditzCyber0x/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/banditzCyber0x/CVE-2024-4956.svg)
- [https://github.com/codeb0ss/CVE-2024-4956-PoC](https://github.com/codeb0ss/CVE-2024-4956-PoC) :  ![starts](https://img.shields.io/github/stars/codeb0ss/CVE-2024-4956-PoC.svg) ![forks](https://img.shields.io/github/forks/codeb0ss/CVE-2024-4956-PoC.svg)
- [https://github.com/gmh5225/CVE-2024-4956](https://github.com/gmh5225/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/gmh5225/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/gmh5225/CVE-2024-4956.svg)
- [https://github.com/eoslvs/CVE-2024-4956](https://github.com/eoslvs/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/eoslvs/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/eoslvs/CVE-2024-4956.svg)
- [https://github.com/GoatSecurity/CVE-2024-4956](https://github.com/GoatSecurity/CVE-2024-4956) :  ![starts](https://img.shields.io/github/stars/GoatSecurity/CVE-2024-4956.svg) ![forks](https://img.shields.io/github/forks/GoatSecurity/CVE-2024-4956.svg)
- [https://github.com/thinhap/CVE-2024-4956-PoC](https://github.com/thinhap/CVE-2024-4956-PoC) :  ![starts](https://img.shields.io/github/stars/thinhap/CVE-2024-4956-PoC.svg) ![forks](https://img.shields.io/github/forks/thinhap/CVE-2024-4956-PoC.svg)


## CVE-2024-4875
 The HT Mega &#8211; Absolute Addons For Elementor plugin for WordPress is vulnerable to unauthorized modification of data|loss of data due to a missing capability check on the 'ajax_dismiss' function in versions up to, and including, 2.5.2. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to update options such as users_can_register, which can lead to unauthorized user registration.

- [https://github.com/RandomRobbieBF/CVE-2024-4875](https://github.com/RandomRobbieBF/CVE-2024-4875) :  ![starts](https://img.shields.io/github/stars/RandomRobbieBF/CVE-2024-4875.svg) ![forks](https://img.shields.io/github/forks/RandomRobbieBF/CVE-2024-4875.svg)


## CVE-2024-4761
 Out of bounds write in V8 in Google Chrome prior to 124.0.6367.207 allowed a remote attacker to perform an out of bounds memory write via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/michredteam/CVE-2024-4761](https://github.com/michredteam/CVE-2024-4761) :  ![starts](https://img.shields.io/github/stars/michredteam/CVE-2024-4761.svg) ![forks](https://img.shields.io/github/forks/michredteam/CVE-2024-4761.svg)


## CVE-2024-4701
 A path traversal issue potentially leading to remote code execution in Genie for all versions prior to 4.3.18

- [https://github.com/JoeBeeton/CVE-2024-4701-POC](https://github.com/JoeBeeton/CVE-2024-4701-POC) :  ![starts](https://img.shields.io/github/stars/JoeBeeton/CVE-2024-4701-POC.svg) ![forks](https://img.shields.io/github/forks/JoeBeeton/CVE-2024-4701-POC.svg)


## CVE-2024-4443
 The Business Directory Plugin &#8211; Easy Listing Directories for WordPress plugin for WordPress is vulnerable to time-based SQL Injection via the &#8216;listingfields&#8217; parameter in all versions up to, and including, 6.4.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for unauthenticated attackers to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/truonghuuphuc/CVE-2024-4443-Poc](https://github.com/truonghuuphuc/CVE-2024-4443-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-4443-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-4443-Poc.svg)


## CVE-2024-4439
 WordPress Core is vulnerable to Stored Cross-Site Scripting via user display names in the Avatar block in various versions up to 6.5.2 due to insufficient output escaping on the display name. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page. In addition, it also makes it possible for unauthenticated attackers to inject arbitrary web scripts in pages that have the comment block present and display the comment author's avatar.

- [https://github.com/d0rb/CVE-2024-4439](https://github.com/d0rb/CVE-2024-4439) :  ![starts](https://img.shields.io/github/stars/d0rb/CVE-2024-4439.svg) ![forks](https://img.shields.io/github/forks/d0rb/CVE-2024-4439.svg)
- [https://github.com/MielPopsssssss/CVE-2024-4439](https://github.com/MielPopsssssss/CVE-2024-4439) :  ![starts](https://img.shields.io/github/stars/MielPopsssssss/CVE-2024-4439.svg) ![forks](https://img.shields.io/github/forks/MielPopsssssss/CVE-2024-4439.svg)
- [https://github.com/xssor-dz/-CVE-2024-4439](https://github.com/xssor-dz/-CVE-2024-4439) :  ![starts](https://img.shields.io/github/stars/xssor-dz/-CVE-2024-4439.svg) ![forks](https://img.shields.io/github/forks/xssor-dz/-CVE-2024-4439.svg)


## CVE-2024-4367
 A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox &lt; 126, Firefox ESR &lt; 115.11, and Thunderbird &lt; 115.11.

- [https://github.com/s4vvysec/CVE-2024-4367-POC](https://github.com/s4vvysec/CVE-2024-4367-POC) :  ![starts](https://img.shields.io/github/stars/s4vvysec/CVE-2024-4367-POC.svg) ![forks](https://img.shields.io/github/forks/s4vvysec/CVE-2024-4367-POC.svg)
- [https://github.com/LOURC0D3/CVE-2024-4367-PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC) :  ![starts](https://img.shields.io/github/stars/LOURC0D3/CVE-2024-4367-PoC.svg) ![forks](https://img.shields.io/github/forks/LOURC0D3/CVE-2024-4367-PoC.svg)
- [https://github.com/spaceraccoon/detect-cve-2024-4367](https://github.com/spaceraccoon/detect-cve-2024-4367) :  ![starts](https://img.shields.io/github/stars/spaceraccoon/detect-cve-2024-4367.svg) ![forks](https://img.shields.io/github/forks/spaceraccoon/detect-cve-2024-4367.svg)
- [https://github.com/avalahEE/pdfjs_disable_eval](https://github.com/avalahEE/pdfjs_disable_eval) :  ![starts](https://img.shields.io/github/stars/avalahEE/pdfjs_disable_eval.svg) ![forks](https://img.shields.io/github/forks/avalahEE/pdfjs_disable_eval.svg)


## CVE-2024-4352
 The Tutor LMS Pro plugin for WordPress is vulnerable to unauthorized access of data, modification of data, loss of data due to a missing capability check on the 'get_calendar_materials' function. The plugin is also vulnerable to SQL Injection via the &#8216;year&#8217; parameter of that function due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query. This makes it possible for authenticated attackers, with subscriber-level permissions and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/truonghuuphuc/CVE-2024-4352-Poc](https://github.com/truonghuuphuc/CVE-2024-4352-Poc) :  ![starts](https://img.shields.io/github/stars/truonghuuphuc/CVE-2024-4352-Poc.svg) ![forks](https://img.shields.io/github/forks/truonghuuphuc/CVE-2024-4352-Poc.svg)


## CVE-2023-32233
 In the Linux kernel through 6.3.1, a use-after-free in Netfilter nf_tables when processing batch requests can be abused to perform arbitrary read and write operations on kernel memory. Unprivileged local users can obtain root privileges. This occurs because anonymous sets are mishandled.

- [https://github.com/rootkalilocalhost/CVE-2023-32233](https://github.com/rootkalilocalhost/CVE-2023-32233) :  ![starts](https://img.shields.io/github/stars/rootkalilocalhost/CVE-2023-32233.svg) ![forks](https://img.shields.io/github/forks/rootkalilocalhost/CVE-2023-32233.svg)


## CVE-2023-22527
 A template injection vulnerability on older versions of Confluence Data Center and Server allows an unauthenticated attacker to achieve RCE on an affected instance. Customers using an affected version must take immediate action. Most recent supported versions of Confluence Data Center and Server are not affected by this vulnerability as it was ultimately mitigated during regular version updates. However, Atlassian recommends that customers take care to install the latest version to protect their instances from non-critical vulnerabilities outlined in Atlassian&#8217;s January Security Bulletin.

- [https://github.com/BBD-YZZ/Confluence-RCE](https://github.com/BBD-YZZ/Confluence-RCE) :  ![starts](https://img.shields.io/github/stars/BBD-YZZ/Confluence-RCE.svg) ![forks](https://img.shields.io/github/forks/BBD-YZZ/Confluence-RCE.svg)


## CVE-2022-26134
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are from 1.3.0 before 7.4.17, from 7.13.0 before 7.13.7, from 7.14.0 before 7.14.3, from 7.15.0 before 7.15.2, from 7.16.0 before 7.16.4, from 7.17.0 before 7.17.4, and from 7.18.0 before 7.18.1.

- [https://github.com/BBD-YZZ/Confluence-RCE](https://github.com/BBD-YZZ/Confluence-RCE) :  ![starts](https://img.shields.io/github/stars/BBD-YZZ/Confluence-RCE.svg) ![forks](https://img.shields.io/github/forks/BBD-YZZ/Confluence-RCE.svg)


## CVE-2022-0995
 An out-of-bounds (OOB) memory write flaw was found in the Linux kernel&#8217;s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

- [https://github.com/rootkalilocalhost/CVE-2022-0995](https://github.com/rootkalilocalhost/CVE-2022-0995) :  ![starts](https://img.shields.io/github/stars/rootkalilocalhost/CVE-2022-0995.svg) ![forks](https://img.shields.io/github/forks/rootkalilocalhost/CVE-2022-0995.svg)


## CVE-2022-0165
 The Page Builder KingComposer WordPress plugin through 2.9.6 does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action available to both unauthenticated and authenticated users

- [https://github.com/Cappricio-Securities/CVE-2022-0165](https://github.com/Cappricio-Securities/CVE-2022-0165) :  ![starts](https://img.shields.io/github/stars/Cappricio-Securities/CVE-2022-0165.svg) ![forks](https://img.shields.io/github/forks/Cappricio-Securities/CVE-2022-0165.svg)


## CVE-2021-43798
 Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `&lt;grafana_host_url&gt;/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.

- [https://github.com/xchg-rax-rax/CVE-2021-43798](https://github.com/xchg-rax-rax/CVE-2021-43798) :  ![starts](https://img.shields.io/github/stars/xchg-rax-rax/CVE-2021-43798.svg) ![forks](https://img.shields.io/github/forks/xchg-rax-rax/CVE-2021-43798.svg)


## CVE-2021-26084
 In affected versions of Confluence Server and Data Center, an OGNL injection vulnerability exists that would allow an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance. The affected versions are before version 6.13.23, from version 6.14.0 before 7.4.11, from version 7.5.0 before 7.11.6, and from version 7.12.0 before 7.12.5.

- [https://github.com/BBD-YZZ/Confluence-RCE](https://github.com/BBD-YZZ/Confluence-RCE) :  ![starts](https://img.shields.io/github/stars/BBD-YZZ/Confluence-RCE.svg) ![forks](https://img.shields.io/github/forks/BBD-YZZ/Confluence-RCE.svg)


## CVE-2021-4045
 TP-Link Tapo C200 IP camera, on its 1.1.15 firmware version and below, is affected by an unauthenticated RCE vulnerability, present in the uhttpd binary running by default as root. The exploitation of this vulnerability allows an attacker to take full control of the camera.

- [https://github.com/jeffbezosispogg/CVE-2021-4045](https://github.com/jeffbezosispogg/CVE-2021-4045) :  ![starts](https://img.shields.io/github/stars/jeffbezosispogg/CVE-2021-4045.svg) ![forks](https://img.shields.io/github/forks/jeffbezosispogg/CVE-2021-4045.svg)


## CVE-2021-1675
 Windows Print Spooler Remote Code Execution Vulnerability

- [https://github.com/B34MR/zeroscan](https://github.com/B34MR/zeroscan) :  ![starts](https://img.shields.io/github/stars/B34MR/zeroscan.svg) ![forks](https://img.shields.io/github/forks/B34MR/zeroscan.svg)


## CVE-2020-1472
 An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC). An attacker who successfully exploited the vulnerability could run a specially crafted application on a device on the network. To exploit the vulnerability, an unauthenticated attacker would be required to use MS-NRPC to connect to a domain controller to obtain domain administrator access. Microsoft is addressing the vulnerability in a phased two-part rollout. These updates address the vulnerability by modifying how Netlogon handles the usage of Netlogon secure channels. For guidelines on how to manage the changes required for this vulnerability and more information on the phased rollout, see How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472 (updated September 28, 2020). When the second phase of Windows updates become available in Q1 2021, customers will be notified via a revision to this security vulnerability. If you wish to be notified when these updates are released, we recommend that you register for the security notifications mailer to be alerted of content changes to this advisory. See Microsoft Technical Security Notifications.

- [https://github.com/B34MR/zeroscan](https://github.com/B34MR/zeroscan) :  ![starts](https://img.shields.io/github/stars/B34MR/zeroscan.svg) ![forks](https://img.shields.io/github/forks/B34MR/zeroscan.svg)

