# Update 2023-02-15
## CVE-2023-25727
 In phpMyAdmin before 4.9.11 and 5.x before 5.2.1, an authenticated user can trigger XSS by uploading a crafted .sql file through the drag-and-drop interface.

- [https://github.com/Live-Hack-CVE/CVE-2023-25727](https://github.com/Live-Hack-CVE/CVE-2023-25727) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25727.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25727.svg)


## CVE-2023-25719
 ConnectWise Control before 22.9.10032 (formerly known as ScreenConnect) fails to validate user-supplied parameters such as the Bin/ConnectWiseControl.Client.exe h parameter. This results in reflected data and injection of malicious code into a downloaded executable. The executable can be used to execute malicious queries or as a denial-of-service vector.

- [https://github.com/Live-Hack-CVE/CVE-2023-25719](https://github.com/Live-Hack-CVE/CVE-2023-25719) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25719.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25719.svg)


## CVE-2023-25718
 The cryptographic code signing process and controls on ConnectWise Control through 22.9.10032 (formerly known as ScreenConnect) are cryptographically flawed. An attacker can remotely generate or locally alter file contents and bypass code-signing controls. This can be used to execute code as a trusted application provider, escalate privileges, or execute arbitrary commands in the context of the user. The attacker tampers with a trusted, signed executable in transit.

- [https://github.com/Live-Hack-CVE/CVE-2023-25718](https://github.com/Live-Hack-CVE/CVE-2023-25718) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25718.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25718.svg)


## CVE-2023-25717
 Ruckus Wireless Admin through 10.4 allows Remote Code Execution via an unauthenticated HTTP GET Request, as demonstrated by a /forms/doLogin?login_username=admin&amp;password=password$(curl substring.

- [https://github.com/Live-Hack-CVE/CVE-2023-25717](https://github.com/Live-Hack-CVE/CVE-2023-25717) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25717.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25717.svg)


## CVE-2023-25572
 react-admin is a frontend framework for building browser applications on top of REST/GraphQL APIs. react-admin prior to versions 3.19.12 and 4.7.6, along with ra-ui-materialui prior to 3.19.12 and 4.7.6, are vulnerable to cross-site scripting. All React applications built with react-admin and using the `&lt;RichTextField&gt;` are affected. `&lt;RichTextField&gt;` outputs the field value using `dangerouslySetInnerHTML` without client-side sanitization. If the data isn't sanitized server-side, this opens a possible cross-site scripting (XSS) attack. Versions 3.19.12 and 4.7.6 now use `DOMPurify` to escape the HTML before outputting it with React and `dangerouslySetInnerHTML`. Users who already sanitize HTML data server-side do not need to upgrade. As a workaround, users may replace the `&lt;RichTextField&gt;` by a custom field doing sanitization by hand.

- [https://github.com/Live-Hack-CVE/CVE-2023-25572](https://github.com/Live-Hack-CVE/CVE-2023-25572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25572.svg)


## CVE-2023-25241
 bgERP v22.31 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the Search parameter.

- [https://github.com/Live-Hack-CVE/CVE-2023-25241](https://github.com/Live-Hack-CVE/CVE-2023-25241) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25241.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25241.svg)


## CVE-2023-25240
 An improper SameSite Attribute vulnerability in pimCore v10.5.15 allows attackers to execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2023-25240](https://github.com/Live-Hack-CVE/CVE-2023-25240) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25240.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25240.svg)


## CVE-2023-25162
 Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Nextcloud Server prior to 24.0.8 and 23.0.12 and Nextcloud Enterprise server prior to 24.0.8 and 23.0.12 are vulnerable to server-side request forgery (SSRF). Attackers can leverage enclosed alphanumeric payloads to bypass IP filters and gain SSRF, which would allow an attacker to read crucial metadata if the server is hosted on the AWS platform. Nextcloud Server 24.0.8 and 23.0.2 and Nextcloud Enterprise Server 24.0.8 and 23.0.12 contain a patch for this issue. No known workarounds are available.

- [https://github.com/Live-Hack-CVE/CVE-2023-25162](https://github.com/Live-Hack-CVE/CVE-2023-25162) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25162.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25162.svg)


## CVE-2023-25161
 Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform. Nextcloud Server and Nextcloud Enterprise Server prior to versions 25.0.1 24.0.8, and 23.0.12 missing rate limiting on password reset functionality. This could result in service slowdown, storage overflow, or cost impact when using external email services. Users should upgrade to Nextcloud Server 25.0.1, 24.0.8, or 23.0.12 or Nextcloud Enterprise Server 25.0.1, 24.0.8, or 23.0.12 to receive a patch. No known workarounds are available.

- [https://github.com/Live-Hack-CVE/CVE-2023-25161](https://github.com/Live-Hack-CVE/CVE-2023-25161) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25161.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25161.svg)


## CVE-2023-25160
 Nextcloud Mail is an email app for the Nextcloud home server platform. Prior to versions 2.2.1, 1.14.5, 1.12.9, and 1.11.8, an attacker can access the mail box by ID getting the subjects and the first characters of the emails. Users should upgrade to Mail 2.2.1 for Nextcloud 25, Mail 1.14.5 for Nextcloud 22-24, Mail 1.12.9 for Nextcloud 21, or Mail 1.11.8 for Nextcloud 20 to receive a patch. No known workarounds are available.

- [https://github.com/Live-Hack-CVE/CVE-2023-25160](https://github.com/Live-Hack-CVE/CVE-2023-25160) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25160.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25160.svg)


## CVE-2023-25159
 Nextcloud Server is the file server software for Nextcloud, a self-hosted productivity platform, and Nextcloud Office is a document collaboration app for the same platform. Nextcloud Server 24.0.x prior to 24.0.8 and 25.0.x prior to 25.0.1, Nextcloud Enterprise Server 24.0.x prior to 24.0.8 and 25.0.x prior to 25.0.1, and Nextcloud Office (Richdocuments) App 6.x prior to 6.3.1 and 7.x prior to 7.0.1 have previews accessible without a watermark. The download should be hidden and the watermark should get applied. This issue is fixed in Nextcloud Server 25.0.1 and 24.0.8, Nextcloud Enterprise Server 25.0.1 and 24.0.8, and Nextcloud Office (Richdocuments) App 7.0.1 (for 25) and 6.3.1 (for 24). No known workarounds are available.

- [https://github.com/Live-Hack-CVE/CVE-2023-25159](https://github.com/Live-Hack-CVE/CVE-2023-25159) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-25159.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-25159.svg)


## CVE-2023-24804
 The ownCloud Android app allows ownCloud users to access, share, and edit files and folders. Prior to version 3.0, the app has an incomplete fix for a path traversal issue and is vulnerable to two bypass methods. The bypasses may lead to information disclosure when uploading the app&#8217;s internal files, and to arbitrary file write when uploading plain text files (although limited by the .txt extension). Version 3.0 fixes the reported bypasses.

- [https://github.com/Live-Hack-CVE/CVE-2023-24804](https://github.com/Live-Hack-CVE/CVE-2023-24804) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24804.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24804.svg)


## CVE-2023-24648
 Zstore v6.6.0 was discovered to contain a cross-site scripting (XSS) vulnerability via the component /index.php.

- [https://github.com/Live-Hack-CVE/CVE-2023-24648](https://github.com/Live-Hack-CVE/CVE-2023-24648) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24648.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24648.svg)


## CVE-2023-24647
 Food Ordering System v2.0 was discovered to contain a SQL injection vulnerability via the email parameter.

- [https://github.com/Live-Hack-CVE/CVE-2023-24647](https://github.com/Live-Hack-CVE/CVE-2023-24647) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24647.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24647.svg)


## CVE-2023-24646
 An arbitrary file upload vulnerability in the component /fos/admin/ajax.php of Food Ordering System v2.0 allows attackers to execute arbitrary code via a crafted PHP file.

- [https://github.com/Live-Hack-CVE/CVE-2023-24646](https://github.com/Live-Hack-CVE/CVE-2023-24646) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24646.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24646.svg)


## CVE-2023-24619
 Redpanda before 22.3.12 discloses cleartext AWS credentials. The import functionality in the rpk binary logs an AWS Access Key ID and Secret in cleartext to standard output, allowing a local user to view the key in the console, or in Kubernetes logs if stdout output is collected. The fixed versions are 22.3.12, 22.2.10, and 22.1.12.

- [https://github.com/Live-Hack-CVE/CVE-2023-24619](https://github.com/Live-Hack-CVE/CVE-2023-24619) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24619.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24619.svg)


## CVE-2023-24572
 Dell Command | Integration Suite for System Center, versions before 6.4.0 contain an arbitrary folder delete vulnerability during uninstallation. A locally authenticated malicious user may potentially exploit this vulnerability leading to arbitrary folder deletion.

- [https://github.com/Live-Hack-CVE/CVE-2023-24572](https://github.com/Live-Hack-CVE/CVE-2023-24572) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24572.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24572.svg)


## CVE-2023-24188
 ureport v2.2.9 was discovered to contain an arbitrary file deletion vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-24188](https://github.com/Live-Hack-CVE/CVE-2023-24188) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24188.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24188.svg)


## CVE-2023-24086
 SLIMS v9.5.2 was discovered to contain a reflected cross-site scripting (XSS) vulnerability via the component /customs/loan_by_class.php?reportView.

- [https://github.com/Live-Hack-CVE/CVE-2023-24086](https://github.com/Live-Hack-CVE/CVE-2023-24086) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24086.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24086.svg)


## CVE-2023-24084
 ChiKoi v1.0 was discovered to contain a SQL injection vulnerability via the load_file function.

- [https://github.com/Live-Hack-CVE/CVE-2023-24084](https://github.com/Live-Hack-CVE/CVE-2023-24084) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-24084.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-24084.svg)


## CVE-2023-24055
 ** DISPUTED ** KeePass through 2.53 (in a default installation) allows an attacker, who has write access to the XML configuration file, to obtain the cleartext passwords by adding an export trigger. NOTE: the vendor's position is that the password database is not intended to be secure against an attacker who has that level of access to the local PC.

- [https://github.com/zwlsix/KeePass-CVE-2023-24055](https://github.com/zwlsix/KeePass-CVE-2023-24055) :  ![starts](https://img.shields.io/github/stars/zwlsix/KeePass-CVE-2023-24055.svg) ![forks](https://img.shields.io/github/forks/zwlsix/KeePass-CVE-2023-24055.svg)


## CVE-2023-23948
 The ownCloud Android app allows ownCloud users to access, share, and edit files and folders. Version 2.21.1 of the ownCloud Android app is vulnerable to SQL injection in `FileContentProvider.kt`. This issue can lead to information disclosure. Two databases, `filelist` and `owncloud_database`, are affected. In version 3.0, the `filelist` database was deprecated. However, injections affecting `owncloud_database` remain relevant as of version 3.0.

- [https://github.com/Live-Hack-CVE/CVE-2023-23948](https://github.com/Live-Hack-CVE/CVE-2023-23948) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23948.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23948.svg)


## CVE-2023-23937
 Pimcore is an Open Source Data &amp; Experience Management Platform: PIM, MDM, CDP, DAM, DXP/CMS &amp; Digital Commerce. The upload functionality for updating user profile does not properly validate the file content-type, allowing any authenticated user to bypass this security check by adding a valid signature (p.e. GIF89) and sending any invalid content-type. This could allow an authenticated attacker to upload HTML files with JS content that will be executed in the context of the domain. This issue has been patched in version 10.5.16.

- [https://github.com/Live-Hack-CVE/CVE-2023-23937](https://github.com/Live-Hack-CVE/CVE-2023-23937) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23937.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23937.svg)


## CVE-2023-23697
 Dell Command | Intel vPro Out of Band, versions before 4.4.0, contain an arbitrary folder delete vulnerability during uninstallation. A locally authenticated malicious user may potentially exploit this vulnerability leading to arbitrary folder deletion.

- [https://github.com/Live-Hack-CVE/CVE-2023-23697](https://github.com/Live-Hack-CVE/CVE-2023-23697) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23697.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23697.svg)


## CVE-2023-23553
 Control By Web X-400 devices are vulnerable to a cross-site scripting attack, which could result in private and session information being transferred to the attacker.

- [https://github.com/Live-Hack-CVE/CVE-2023-23553](https://github.com/Live-Hack-CVE/CVE-2023-23553) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23553.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23553.svg)


## CVE-2023-23551
 Control By Web X-600M devices run Lua scripts and are vulnerable to code injection, which could allow an attacker to remotely execute arbitrary code.

- [https://github.com/Live-Hack-CVE/CVE-2023-23551](https://github.com/Live-Hack-CVE/CVE-2023-23551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-23551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-23551.svg)


## CVE-2023-22854
 The ccmweb component of Mitel MiContact Center Business server 9.2.2.0 through 9.4.1.0 could allow an unauthenticated attacker to download arbitrary files, due to insufficient restriction of URL parameters. A successful exploit could allow access to sensitive information.

- [https://github.com/Live-Hack-CVE/CVE-2023-22854](https://github.com/Live-Hack-CVE/CVE-2023-22854) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22854.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22854.svg)


## CVE-2023-22367
 Ichiran App for iOS versions prior to 3.1.0 and Ichiran App for Android versions prior to 3.1.0 improperly verify server certificates, which may allow a remote unauthenticated attacker to eavesdrop on an encrypted communication via a man-in-the-middle attack.

- [https://github.com/Live-Hack-CVE/CVE-2023-22367](https://github.com/Live-Hack-CVE/CVE-2023-22367) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22367.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22367.svg)


## CVE-2023-22362
 SUSHIRO App for Android outputs sensitive information to the log file, which may result in an attacker obtaining a credential information from the log file. Affected products/versions are as follows: SUSHIRO Ver.4.0.31, Thailand SUSHIRO Ver.1.0.0, Hong Kong SUSHIRO Ver.3.0.2, Singapore SUSHIRO Ver.2.0.0, and Taiwan SUSHIRO Ver.2.0.1

- [https://github.com/Live-Hack-CVE/CVE-2023-22362](https://github.com/Live-Hack-CVE/CVE-2023-22362) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22362.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22362.svg)


## CVE-2023-22360
 Use-after free vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier due to lack of error handling process even when an error was detected. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22360](https://github.com/Live-Hack-CVE/CVE-2023-22360) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22360.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22360.svg)


## CVE-2023-22353
 Out-of-bound read vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier because the end of data cannot be verified when processing control management information. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22353](https://github.com/Live-Hack-CVE/CVE-2023-22353) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22353.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22353.svg)


## CVE-2023-22350
 Out-of-bound read vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier because the end of data cannot be verified when processing parts management information. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22350](https://github.com/Live-Hack-CVE/CVE-2023-22350) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22350.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22350.svg)


## CVE-2023-22349
 Out-of-bound read vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier because the end of data cannot be verified when processing screen management information. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22349](https://github.com/Live-Hack-CVE/CVE-2023-22349) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22349.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22349.svg)


## CVE-2023-22347
 Out-of-bound read vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier because the end of data cannot be verified when processing file structure information. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22347](https://github.com/Live-Hack-CVE/CVE-2023-22347) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22347.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22347.svg)


## CVE-2023-22346
 Out-of-bound read vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier because the end of data cannot be verified when processing template information. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22346](https://github.com/Live-Hack-CVE/CVE-2023-22346) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22346.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22346.svg)


## CVE-2023-22345
 Out-of-bound write vulnerability exists in Screen Creator Advance 2 Ver.0.1.1.4 Build01 and earlier due to lack of error handling process when out of specification errors are detected. Having a user of Screen Creator Advance 2 to open a specially crafted project file may lead to information disclosure and/or arbitrary code execution.

- [https://github.com/Live-Hack-CVE/CVE-2023-22345](https://github.com/Live-Hack-CVE/CVE-2023-22345) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22345.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22345.svg)


## CVE-2023-21608
 Adobe Acrobat Reader versions 22.003.20282 (and earlier), 22.003.20281 (and earlier) and 20.005.30418 (and earlier) are affected by a Use After Free vulnerability that could result in arbitrary code execution in the context of the current user. Exploitation of this issue requires user interaction in that a victim must open a malicious file.

- [https://github.com/Malwareman007/CVE-2023-21608](https://github.com/Malwareman007/CVE-2023-21608) :  ![starts](https://img.shields.io/github/stars/Malwareman007/CVE-2023-21608.svg) ![forks](https://img.shields.io/github/forks/Malwareman007/CVE-2023-21608.svg)


## CVE-2023-0819
 Heap-based Buffer Overflow in GitHub repository gpac/gpac prior to v2.3.0-DEV.

- [https://github.com/Live-Hack-CVE/CVE-2023-0819](https://github.com/Live-Hack-CVE/CVE-2023-0819) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0819.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0819.svg)


## CVE-2023-0818
 Off-by-one Error in GitHub repository gpac/gpac prior to v2.3.0-DEV.

- [https://github.com/Live-Hack-CVE/CVE-2023-0818](https://github.com/Live-Hack-CVE/CVE-2023-0818) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0818.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0818.svg)


## CVE-2023-0817
 Buffer Over-read in GitHub repository gpac/gpac prior to v2.3.0-DEV.

- [https://github.com/Live-Hack-CVE/CVE-2023-0817](https://github.com/Live-Hack-CVE/CVE-2023-0817) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0817.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0817.svg)


## CVE-2023-0810
 Cross-site Scripting (XSS) - Stored in GitHub repository btcpayserver/btcpayserver prior to 1.7.11.

- [https://github.com/Live-Hack-CVE/CVE-2023-0810](https://github.com/Live-Hack-CVE/CVE-2023-0810) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0810.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0810.svg)


## CVE-2023-0808
 A vulnerability was found in Deye/Revolt/Bosswerk Inverter MW3_15U_5406_1.47/MW3_15U_5406_1.471. It has been rated as problematic. This issue affects some unknown processing of the component Access Point Setting Handler. The manipulation with the input 12345678 leads to use of hard-coded password. It is possible to launch the attack on the physical device. The exploit has been disclosed to the public and may be used. Upgrading to version MW3_16U_5406_1.53 is able to address this issue. It is recommended to upgrade the affected component. The identifier VDB-220769 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2023-0808](https://github.com/Live-Hack-CVE/CVE-2023-0808) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0808.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0808.svg)


## CVE-2023-0804
 LibTIFF 4.4.0 has an out-of-bounds write in tiffcrop in tools/tiffcrop.c:3609, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 33aee127.

- [https://github.com/Live-Hack-CVE/CVE-2023-0804](https://github.com/Live-Hack-CVE/CVE-2023-0804) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0804.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0804.svg)


## CVE-2023-0803
 LibTIFF 4.4.0 has an out-of-bounds write in tiffcrop in tools/tiffcrop.c:3516, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 33aee127.

- [https://github.com/Live-Hack-CVE/CVE-2023-0803](https://github.com/Live-Hack-CVE/CVE-2023-0803) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0803.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0803.svg)


## CVE-2023-0802
 LibTIFF 4.4.0 has an out-of-bounds write in tiffcrop in tools/tiffcrop.c:3724, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 33aee127.

- [https://github.com/Live-Hack-CVE/CVE-2023-0802](https://github.com/Live-Hack-CVE/CVE-2023-0802) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0802.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0802.svg)


## CVE-2023-0801
 LibTIFF 4.4.0 has an out-of-bounds write in tiffcrop in libtiff/tif_unix.c:368, invoked by tools/tiffcrop.c:2903 and tools/tiffcrop.c:6778, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 33aee127.

- [https://github.com/Live-Hack-CVE/CVE-2023-0801](https://github.com/Live-Hack-CVE/CVE-2023-0801) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0801.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0801.svg)


## CVE-2023-0800
 LibTIFF 4.4.0 has an out-of-bounds write in tiffcrop in tools/tiffcrop.c:3502, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit 33aee127.

- [https://github.com/Live-Hack-CVE/CVE-2023-0800](https://github.com/Live-Hack-CVE/CVE-2023-0800) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0800.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0800.svg)


## CVE-2023-0799
 LibTIFF 4.4.0 has an out-of-bounds read in tiffcrop in tools/tiffcrop.c:3701, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit afaabc3e.

- [https://github.com/Live-Hack-CVE/CVE-2023-0799](https://github.com/Live-Hack-CVE/CVE-2023-0799) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0799.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0799.svg)


## CVE-2023-0798
 LibTIFF 4.4.0 has an out-of-bounds read in tiffcrop in tools/tiffcrop.c:3400, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit afaabc3e.

- [https://github.com/Live-Hack-CVE/CVE-2023-0798](https://github.com/Live-Hack-CVE/CVE-2023-0798) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0798.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0798.svg)


## CVE-2023-0797
 LibTIFF 4.4.0 has an out-of-bounds read in tiffcrop in libtiff/tif_unix.c:368, invoked by tools/tiffcrop.c:2903 and tools/tiffcrop.c:6921, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit afaabc3e.

- [https://github.com/Live-Hack-CVE/CVE-2023-0797](https://github.com/Live-Hack-CVE/CVE-2023-0797) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0797.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0797.svg)


## CVE-2023-0796
 LibTIFF 4.4.0 has an out-of-bounds read in tiffcrop in tools/tiffcrop.c:3592, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit afaabc3e.

- [https://github.com/Live-Hack-CVE/CVE-2023-0796](https://github.com/Live-Hack-CVE/CVE-2023-0796) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0796.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0796.svg)


## CVE-2023-0795
 LibTIFF 4.4.0 has an out-of-bounds read in tiffcrop in tools/tiffcrop.c:3488, allowing attackers to cause a denial-of-service via a crafted tiff file. For users that compile libtiff from sources, the fix is available with commit afaabc3e.

- [https://github.com/Live-Hack-CVE/CVE-2023-0795](https://github.com/Live-Hack-CVE/CVE-2023-0795) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0795.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0795.svg)


## CVE-2023-0776
 Baicells Nova 436Q, Nova 430E, Nova 430I, and Neutrino 430 LTE TDD eNodeB devices with firmware through QRTB 2.12.7 are vulnerable to remote shell code exploitation via HTTP command injections. Commands are executed using pre-login execution and executed with root permissions. The following methods below have been tested and validated by a 3rd party analyst and has been confirmed exploitable special thanks to Rustam Amin for providing the steps to reproduce.

- [https://github.com/Live-Hack-CVE/CVE-2023-0776](https://github.com/Live-Hack-CVE/CVE-2023-0776) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0776.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0776.svg)


## CVE-2023-0518
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.0 before 15.6.7, all versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. It was possible to trigger a DoS attack by uploading a malicious Helm chart.

- [https://github.com/Live-Hack-CVE/CVE-2023-0518](https://github.com/Live-Hack-CVE/CVE-2023-0518) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0518.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0518.svg)


## CVE-2023-0034
 The JetWidgets For Elementor WordPress plugin through 1.0.13 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2023-0034](https://github.com/Live-Hack-CVE/CVE-2023-0034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0034.svg)


## CVE-2022-48323
 Sunlogin Sunflower Simplified (aka Sunflower Simple and Personal) 1.0.1.43315 is vulnerable to a path traversal issue. A remote and unauthenticated attacker can execute arbitrary programs on the victim host by sending a crafted HTTP request, as demonstrated by /check?cmd=ping../ followed by the pathname of the powershell.exe program.

- [https://github.com/Live-Hack-CVE/CVE-2022-48323](https://github.com/Live-Hack-CVE/CVE-2022-48323) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48323.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48323.svg)


## CVE-2022-48322
 NETGEAR Nighthawk WiFi Mesh systems and routers are affected by a stack-based buffer overflow vulnerability. This affects MR60 before 1.1.7.132, MS60 before 1.1.7.132, R6900P before 1.3.3.154, R7000P before 1.3.3.154, R7960P before 1.4.4.94, and R8000P before 1.4.4.94.

- [https://github.com/Live-Hack-CVE/CVE-2022-48322](https://github.com/Live-Hack-CVE/CVE-2022-48322) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48322.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48322.svg)


## CVE-2022-48110
 CKSource CKEditor5 35.4.0 was discovered to contain a cross-site scripting (XSS) vulnerability via the Full Featured CKEditor5 widget.

- [https://github.com/Live-Hack-CVE/CVE-2022-48110](https://github.com/Live-Hack-CVE/CVE-2022-48110) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48110.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48110.svg)


## CVE-2022-48077
 Genymotion Desktop v3.3.2 was discovered to contain a DLL hijacking vulnerability that allows attackers to escalate privileges and execute arbitrary code via a crafted DLL.

- [https://github.com/Live-Hack-CVE/CVE-2022-48077](https://github.com/Live-Hack-CVE/CVE-2022-48077) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-48077.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-48077.svg)


## CVE-2022-47034
 A type juggling vulnerability in the component /auth/fn.php of PlaySMS v1.4.5 and earlier allows attackers to bypass authentication.

- [https://github.com/Live-Hack-CVE/CVE-2022-47034](https://github.com/Live-Hack-CVE/CVE-2022-47034) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-47034.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-47034.svg)


## CVE-2022-45962
 Open Solutions for Education, Inc openSIS Community Edition v8.0 and earlier is vulnerable to SQL Injection via CalendarModal.php.

- [https://github.com/Live-Hack-CVE/CVE-2022-45962](https://github.com/Live-Hack-CVE/CVE-2022-45962) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45962.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45962.svg)


## CVE-2022-45725
 Improper Input Validation in Comfast router CF-WR6110N V2.3.1 allows a remote attacker on the same network to execute arbitrary code on the target via an HTTP POST request

- [https://github.com/Live-Hack-CVE/CVE-2022-45725](https://github.com/Live-Hack-CVE/CVE-2022-45725) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45725.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45725.svg)


## CVE-2022-45724
 Incorrect Access Control in Comfast router CF-WR6110N V2.3.1 allows a remote attacker on the same network to perform any HTTP request to an unauthenticated page to force the server to generate a SESSION_ID, and using this SESSION_ID an attacker can then perform authenticated requests.

- [https://github.com/Live-Hack-CVE/CVE-2022-45724](https://github.com/Live-Hack-CVE/CVE-2022-45724) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45724.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45724.svg)


## CVE-2022-45455
 Local privilege escalation due to incomplete uninstallation cleanup. The following products are affected: Acronis Cyber Protect Home Office (Windows) before build 40107, Acronis Agent (Windows) before build 30025, Acronis Cyber Protect 15 (Windows) before build 30984.

- [https://github.com/Live-Hack-CVE/CVE-2022-45455](https://github.com/Live-Hack-CVE/CVE-2022-45455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45455.svg)


## CVE-2022-45454
 Sensitive information disclosure due to insecure folder permissions. The following products are affected: Acronis Agent (Windows) before build 30161, Acronis Cyber Protect 15 (Windows) before build 30984.

- [https://github.com/Live-Hack-CVE/CVE-2022-45454](https://github.com/Live-Hack-CVE/CVE-2022-45454) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45454.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45454.svg)


## CVE-2022-45285
 Vsourz Digital Advanced Contact form 7 DB Versions 1.7.2 and 1.9.1 is vulnerable to Cross Site Scripting (XSS).

- [https://github.com/Live-Hack-CVE/CVE-2022-45285](https://github.com/Live-Hack-CVE/CVE-2022-45285) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-45285.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-45285.svg)


## CVE-2022-43460
 Driver Distributor v2.2.3.1 and earlier contains a vulnerability where passwords are stored in a recoverable format. If an attacker obtains a configuration file of Driver Distributor, the encrypted administrator's credentials may be decrypted.

- [https://github.com/Live-Hack-CVE/CVE-2022-43460](https://github.com/Live-Hack-CVE/CVE-2022-43460) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-43460.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-43460.svg)


## CVE-2022-41134
 Cross-Site Request Forgery (CSRF) in OptinlyHQ Optinly &#8211; Exit Intent, Newsletter Popups, Gamification &amp; Opt-in Forms plugin &lt;= 1.0.15 versions.

- [https://github.com/Live-Hack-CVE/CVE-2022-41134](https://github.com/Live-Hack-CVE/CVE-2022-41134) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-41134.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-41134.svg)


## CVE-2022-40022
 Microchip Technology (Microsemi) SyncServer S650 was discovered to contain a command injection vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-40022](https://github.com/Live-Hack-CVE/CVE-2022-40022) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-40022.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-40022.svg)


## CVE-2022-34397
 Dell Unisphere for PowerMax vApp, VASA Provider vApp, and Solution Enabler vApp version 10.0.0.5 and below contains an authorization bypass vulnerability, allowing users to perform actions in which they are not authorized.

- [https://github.com/Live-Hack-CVE/CVE-2022-34397](https://github.com/Live-Hack-CVE/CVE-2022-34397) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-34397.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-34397.svg)


## CVE-2022-25937
 Versions of the package glance before 3.0.9 are vulnerable to Directory Traversal that allows users to read files outside the public root directory. This is related to but distinct from the vulnerability reported in [CVE-2018-3715](https://security.snyk.io/vuln/npm:glance:20180129).

- [https://github.com/Live-Hack-CVE/CVE-2022-25937](https://github.com/Live-Hack-CVE/CVE-2022-25937) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-25937.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-25937.svg)


## CVE-2022-4905
 A vulnerability was found in UDX Stateless Media Plugin 3.1.1. It has been declared as problematic. This vulnerability affects the function setup_wizard_interface of the file lib/classes/class-settings.php. The manipulation of the argument settings leads to cross site scripting. The attack can be initiated remotely. Upgrading to version 3.2.0 is able to address this issue. The name of the patch is 6aee7ae0b0beeb2232ce6e1c82aa7e2041ae151a. It is recommended to upgrade the affected component. VDB-220750 is the identifier assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4905](https://github.com/Live-Hack-CVE/CVE-2022-4905) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4905.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4905.svg)


## CVE-2022-4830
 The Paid Memberships Pro WordPress plugin before 2.9.9 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4830](https://github.com/Live-Hack-CVE/CVE-2022-4830) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4830.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4830.svg)


## CVE-2022-4783
 The Youtube Channel Gallery WordPress plugin through 2.4 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4783](https://github.com/Live-Hack-CVE/CVE-2022-4783) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4783.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4783.svg)


## CVE-2022-4759
 The GigPress WordPress plugin before 2.3.28 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4759](https://github.com/Live-Hack-CVE/CVE-2022-4759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4759.svg)


## CVE-2022-4745
 The WP Customer Area WordPress plugin before 8.1.4 does not have CSRF checks when performing some actions such as chmod, mkdir and copy, which could allow attackers to make a logged-in admin perform them and create arbitrary folders, copy file for example.

- [https://github.com/Live-Hack-CVE/CVE-2022-4745](https://github.com/Live-Hack-CVE/CVE-2022-4745) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4745.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4745.svg)


## CVE-2022-4682
 The Lightbox Gallery WordPress plugin before 0.9.5 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4682](https://github.com/Live-Hack-CVE/CVE-2022-4682) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4682.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4682.svg)


## CVE-2022-4678
 The TemplatesNext ToolKit WordPress plugin before 3.2.8 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-4678](https://github.com/Live-Hack-CVE/CVE-2022-4678) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4678.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4678.svg)


## CVE-2022-4656
 The WP Visitor Statistics (Real Time Traffic) WordPress plugin before 6.5 does not validate and escape one of its shortcode attributes, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attack.

- [https://github.com/Live-Hack-CVE/CVE-2022-4656](https://github.com/Live-Hack-CVE/CVE-2022-4656) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4656.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4656.svg)


## CVE-2022-4628
 The Easy PayPal Buy Now Button WordPress plugin before 1.7.4 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4628](https://github.com/Live-Hack-CVE/CVE-2022-4628) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4628.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4628.svg)


## CVE-2022-4580
 The Twenty20 Image Before-After WordPress plugin through 1.5.9 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4580](https://github.com/Live-Hack-CVE/CVE-2022-4580) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4580.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4580.svg)


## CVE-2022-4562
 The Meks Flexible Shortcodes WordPress plugin before 1.3.5 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4562](https://github.com/Live-Hack-CVE/CVE-2022-4562) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4562.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4562.svg)


## CVE-2022-4551
 The Rich Table of Contents WordPress plugin through 1.3.7 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4551](https://github.com/Live-Hack-CVE/CVE-2022-4551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4551.svg)


## CVE-2022-4546
 The Mapwiz WordPress plugin through 1.0.1 does not properly sanitise and escape a parameter before using it in a SQL statement, leading to a SQL injection exploitable by high privilege users such as admin.

- [https://github.com/Live-Hack-CVE/CVE-2022-4546](https://github.com/Live-Hack-CVE/CVE-2022-4546) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4546.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4546.svg)


## CVE-2022-4512
 The Better Font Awesome WordPress plugin before 2.0.4 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks.

- [https://github.com/Live-Hack-CVE/CVE-2022-4512](https://github.com/Live-Hack-CVE/CVE-2022-4512) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4512.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4512.svg)


## CVE-2022-4488
 The Widgets on Pages WordPress plugin through 1.6.0 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4488](https://github.com/Live-Hack-CVE/CVE-2022-4488) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4488.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4488.svg)


## CVE-2022-4473
 The Widget Shortcode WordPress plugin through 0.3.5 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4473](https://github.com/Live-Hack-CVE/CVE-2022-4473) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4473.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4473.svg)


## CVE-2022-4471
 The YARPP WordPress plugin through 5.30.1 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4471](https://github.com/Live-Hack-CVE/CVE-2022-4471) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4471.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4471.svg)


## CVE-2022-4458
 The amr shortcode any widget WordPress plugin through 4.0 does not validate and escape some of its shortcode attributes before outputting them back in the page, which could allow users with a role as low as contributor to perform Stored Cross-Site Scripting attacks which could be used against high privilege users such as admins.

- [https://github.com/Live-Hack-CVE/CVE-2022-4458](https://github.com/Live-Hack-CVE/CVE-2022-4458) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4458.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4458.svg)


## CVE-2022-4455
 A vulnerability, which was classified as problematic, was found in sproctor php-calendar. This affects an unknown part of the file index.php. The manipulation of the argument $_SERVER['PHP_SELF'] leads to cross site scripting. It is possible to initiate the attack remotely. The name of the patch is a2941109b42201c19733127ced763e270a357809. It is recommended to apply a patch to fix this issue. The identifier VDB-215445 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-4455](https://github.com/Live-Hack-CVE/CVE-2022-4455) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4455.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4455.svg)


## CVE-2022-4448
 The GiveWP WordPress plugin before 2.24.0 does not validate and escape some of its shortcode attributes before outputting them back in a page/post where the shortcode is embed, which could allow users with the contributor role and above to perform Stored Cross-Site Scripting attacks

- [https://github.com/Live-Hack-CVE/CVE-2022-4448](https://github.com/Live-Hack-CVE/CVE-2022-4448) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4448.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4448.svg)


## CVE-2022-4445
 The FL3R FeelBox WordPress plugin through 8.1 does not properly sanitise and escape a parameter before using it in a SQL statement via an AJAX action available to unauthenticated users, leading to a SQL injection.

- [https://github.com/Live-Hack-CVE/CVE-2022-4445](https://github.com/Live-Hack-CVE/CVE-2022-4445) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4445.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4445.svg)


## CVE-2022-4138
 A Cross Site Request Forgery issue has been discovered in GitLab CE/EE affecting all versions before 15.6.7, all versions starting from 15.7 before 15.7.6, and all versions starting from 15.8 before 15.8.1. An attacker could take over a project if an Owner or Maintainer uploads a file to a malicious project.

- [https://github.com/Live-Hack-CVE/CVE-2022-4138](https://github.com/Live-Hack-CVE/CVE-2022-4138) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-4138.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-4138.svg)


## CVE-2022-3891
 The WP FullCalendar WordPress plugin before 1.5 does not ensure that the post retrieved via an AJAX action is public and can be accessed by the user making the request, allowing unauthenticated attackers to get the content of arbitrary posts, including draft/private as well as password-protected ones.

- [https://github.com/Live-Hack-CVE/CVE-2022-3891](https://github.com/Live-Hack-CVE/CVE-2022-3891) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3891.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3891.svg)


## CVE-2022-3759
 An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.3 before 15.6.7, all versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. An attacker may upload a crafted CI job artifact zip file in a project that uses dynamic child pipelines and make a sidekiq job allocate a lot of memory. In GitLab instances where Sidekiq is memory-limited, this may cause Denial of Service.

- [https://github.com/Live-Hack-CVE/CVE-2022-3759](https://github.com/Live-Hack-CVE/CVE-2022-3759) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3759.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3759.svg)


## CVE-2022-3625
 A vulnerability was found in Linux Kernel. It has been classified as critical. This affects the function devlink_param_set/devlink_param_get of the file net/core/devlink.c of the component IPsec. The manipulation leads to use after free. It is recommended to apply a patch to fix this issue. The identifier VDB-211929 was assigned to this vulnerability.

- [https://github.com/Live-Hack-CVE/CVE-2022-3625](https://github.com/Live-Hack-CVE/CVE-2022-3625) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3625.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3625.svg)


## CVE-2022-3411
 A lack of length validation in GitLab CE/EE affecting all versions from 12.4 before 15.6.7, 15.7 before 15.7.6, and 15.8 before 15.8.1 allows an authenticated attacker to create a large Issue description via GraphQL which, when repeatedly requested, saturates CPU usage.

- [https://github.com/Live-Hack-CVE/CVE-2022-3411](https://github.com/Live-Hack-CVE/CVE-2022-3411) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3411.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3411.svg)


## CVE-2022-3089
 Echelon SmartServer 2.2 with i.LON Vision 2.2 stores cleartext credentials in a file, which could allow an attacker to obtain cleartext usernames and passwords of the SmartServer. If the attacker obtains the file, then the credentials could be used to control the web user interface and file transfer protocol (FTP) server.

- [https://github.com/Live-Hack-CVE/CVE-2022-3089](https://github.com/Live-Hack-CVE/CVE-2022-3089) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3089.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3089.svg)


## CVE-2022-3082
 The miniOrange Discord Integration WordPress plugin before 2.1.6 does not have authorisation and CSRF in some of its AJAX actions, allowing any logged in users, such as subscriber to call them, and disable the app for example

- [https://github.com/Live-Hack-CVE/CVE-2022-3082](https://github.com/Live-Hack-CVE/CVE-2022-3082) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-3082.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-3082.svg)


## CVE-2022-2611
 Inappropriate implementation in Fullscreen API in Google Chrome on Android prior to 104.0.5112.79 allowed a remote attacker to spoof the contents of the Omnibox (URL bar) via a crafted HTML page.

- [https://github.com/Live-Hack-CVE/CVE-2022-2611](https://github.com/Live-Hack-CVE/CVE-2022-2611) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-2611.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-2611.svg)


## CVE-2022-0355
 Exposure of Sensitive Information to an Unauthorized Actor in NPM simple-get prior to 4.0.1.

- [https://github.com/Live-Hack-CVE/CVE-2022-0355](https://github.com/Live-Hack-CVE/CVE-2022-0355) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2022-0355.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2022-0355.svg)


## CVE-2021-41773
 A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration &quot;require all denied&quot;, these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found to be incomplete, see CVE-2021-42013.

- [https://github.com/iosifache/ApacheRCEEssay](https://github.com/iosifache/ApacheRCEEssay) :  ![starts](https://img.shields.io/github/stars/iosifache/ApacheRCEEssay.svg) ![forks](https://img.shields.io/github/forks/iosifache/ApacheRCEEssay.svg)


## CVE-2021-38295
 In Apache CouchDB, a malicious user with permission to create documents in a database is able to attach a HTML attachment to a document. If a CouchDB admin opens that attachment in a browser, e.g. via the CouchDB admin interface Fauxton, any JavaScript code embedded in that HTML attachment will be executed within the security context of that admin. A similar route is available with the already deprecated _show and _list functionality. This privilege escalation vulnerability allows an attacker to add or remove data in any database or make configuration changes. This issue affected Apache CouchDB prior to 3.1.2

- [https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC](https://github.com/ProfessionallyEvil/CVE-2021-38295-PoC) :  ![starts](https://img.shields.io/github/stars/ProfessionallyEvil/CVE-2021-38295-PoC.svg) ![forks](https://img.shields.io/github/forks/ProfessionallyEvil/CVE-2021-38295-PoC.svg)


## CVE-2021-37379
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek Sphere all firmware versions allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37379](https://github.com/Live-Hack-CVE/CVE-2021-37379) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37379.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37379.svg)


## CVE-2021-37378
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek Cube and Cube Pro firmware version 7.3.x and earlier allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37378](https://github.com/Live-Hack-CVE/CVE-2021-37378) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37378.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37378.svg)


## CVE-2021-37377
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek Brik firmware version 7.2.x and earlier allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37377](https://github.com/Live-Hack-CVE/CVE-2021-37377) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37377.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37377.svg)


## CVE-2021-37376
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek Bond, Bond 2 and Bond Pro firmware version 7.3.x and earlier allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37376](https://github.com/Live-Hack-CVE/CVE-2021-37376) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37376.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37376.svg)


## CVE-2021-37375
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek VidiU / VidiU Mini firmware version 3.0.8 and earlier allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37375](https://github.com/Live-Hack-CVE/CVE-2021-37375) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37375.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37375.svg)


## CVE-2021-37374
 ** UNSUPPORTED WHEN ASSIGNED ** Cross Site Scripting (XSS) vulnerability in Teradek Clip all firmware versions allows remote attackers to run arbitrary code via the Friendly Name field in System Information Settings. NOTE: Vedor states the product has reached End of Life and will not be receiving any firmware updates to address this issue.

- [https://github.com/Live-Hack-CVE/CVE-2021-37374](https://github.com/Live-Hack-CVE/CVE-2021-37374) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37374.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37374.svg)


## CVE-2021-37317
 Directory Traversal vulnerability in Cloud Disk in ASUS RT-AC68U router firmware version before 3.0.0.4.386.41634 allows remote attackers to write arbitrary files via improper sanitation on the target for COPY and MOVE operations.

- [https://github.com/Live-Hack-CVE/CVE-2021-37317](https://github.com/Live-Hack-CVE/CVE-2021-37317) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37317.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37317.svg)


## CVE-2021-37315
 Incorrect Access Control issue discoverd in Cloud Disk in ASUS RT-AC68U router firmware version before 3.0.0.4.386.41634 allows remote attackers to write arbitrary files via improper sanitation on the source for COPY and MOVE operations.

- [https://github.com/Live-Hack-CVE/CVE-2021-37315](https://github.com/Live-Hack-CVE/CVE-2021-37315) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-37315.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-37315.svg)


## CVE-2021-34562
 In PEPPERL+FUCHS WirelessHART-Gateway 3.0.8 it is possible to inject arbitrary JavaScript into the application's response.

- [https://github.com/Live-Hack-CVE/CVE-2021-34562](https://github.com/Live-Hack-CVE/CVE-2021-34562) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2021-34562.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2021-34562.svg)


## CVE-2021-21551
 Dell dbutil_2_3.sys driver contains an insufficient access control vulnerability which may lead to escalation of privileges, denial of service, or information disclosure. Local authenticated user access is required.

- [https://github.com/nanabingies/Driver-RW](https://github.com/nanabingies/Driver-RW) :  ![starts](https://img.shields.io/github/stars/nanabingies/Driver-RW.svg) ![forks](https://img.shields.io/github/forks/nanabingies/Driver-RW.svg)


## CVE-2021-3156
 Sudo before 1.9.5p2 contains an off-by-one error that can result in a heap-based buffer overflow, which allows privilege escalation to root via &quot;sudoedit -s&quot; and a command-line argument that ends with a single backslash character.

- [https://github.com/jm33-m0/CVE-2021-3156](https://github.com/jm33-m0/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/jm33-m0/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/jm33-m0/CVE-2021-3156.svg)
- [https://github.com/freeFV/CVE-2021-3156](https://github.com/freeFV/CVE-2021-3156) :  ![starts](https://img.shields.io/github/stars/freeFV/CVE-2021-3156.svg) ![forks](https://img.shields.io/github/forks/freeFV/CVE-2021-3156.svg)


## CVE-2020-8244
 A buffer over-read vulnerability exists in bl &lt;4.0.3, &lt;3.0.1, &lt;2.2.1, and &lt;1.2.3 which could allow an attacker to supply user input (even typed) that if it ends up in consume() argument and can become negative, the BufferList state can be corrupted, tricking it into exposing uninitialized memory via regular .slice() calls.

- [https://github.com/ossf-cve-benchmark/CVE-2020-8244](https://github.com/ossf-cve-benchmark/CVE-2020-8244) :  ![starts](https://img.shields.io/github/stars/ossf-cve-benchmark/CVE-2020-8244.svg) ![forks](https://img.shields.io/github/forks/ossf-cve-benchmark/CVE-2020-8244.svg)


## CVE-2020-3766
 Adobe Genuine Integrity Service versions Version 6.4 and earlier have an insecure file permissions vulnerability. Successful exploitation could lead to privilege escalation.

- [https://github.com/hessandrew/CVE-2020-3766_APSB20-12](https://github.com/hessandrew/CVE-2020-3766_APSB20-12) :  ![starts](https://img.shields.io/github/stars/hessandrew/CVE-2020-3766_APSB20-12.svg) ![forks](https://img.shields.io/github/forks/hessandrew/CVE-2020-3766_APSB20-12.svg)


## CVE-2020-1362
 An elevation of privilege vulnerability exists in the way that the Windows WalletService handles objects in memory, aka 'Windows WalletService Elevation of Privilege Vulnerability'. This CVE ID is unique from CVE-2020-1344, CVE-2020-1369.

- [https://github.com/Q4n/CVE-2020-1362](https://github.com/Q4n/CVE-2020-1362) :  ![starts](https://img.shields.io/github/stars/Q4n/CVE-2020-1362.svg) ![forks](https://img.shields.io/github/forks/Q4n/CVE-2020-1362.svg)


## CVE-2019-1010065
 The Sleuth Kit 4.6.0 and earlier is affected by: Integer Overflow. The impact is: Opening crafted disk image triggers crash in tsk/fs/hfs_dent.c:237. The component is: Overflow in fls tool used on HFS image. Bug is in tsk/fs/hfs.c file in function hfs_cat_traverse() in lines: 952, 1062. The attack vector is: Victim must open a crafted HFS filesystem image.

- [https://github.com/Live-Hack-CVE/CVE-2019-1010065](https://github.com/Live-Hack-CVE/CVE-2019-1010065) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2019-1010065.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2019-1010065.svg)


## CVE-2019-1579
 Remote Code Execution in PAN-OS 7.1.18 and earlier, PAN-OS 8.0.11-h1 and earlier, and PAN-OS 8.1.2 and earlier with GlobalProtect Portal or GlobalProtect Gateway Interface enabled may allow an unauthenticated remote attacker to execute arbitrary code.

- [https://github.com/securifera/CVE-2019-1579](https://github.com/securifera/CVE-2019-1579) :  ![starts](https://img.shields.io/github/stars/securifera/CVE-2019-1579.svg) ![forks](https://img.shields.io/github/forks/securifera/CVE-2019-1579.svg)
- [https://github.com/Elsfa7-110/CVE-2019-1579](https://github.com/Elsfa7-110/CVE-2019-1579) :  ![starts](https://img.shields.io/github/stars/Elsfa7-110/CVE-2019-1579.svg) ![forks](https://img.shields.io/github/forks/Elsfa7-110/CVE-2019-1579.svg)


## CVE-2015-10079
 A vulnerability was found in juju2143 WalrusIRC 0.0.2. It has been rated as problematic. This issue affects the function parseLinks of the file public/parser.js. The manipulation of the argument text leads to cross site scripting. The attack may be initiated remotely. Upgrading to version 0.0.3 is able to address this issue. The name of the patch is 45fd885895ae13e8d9b3a71e89d59768914f60af. It is recommended to upgrade the affected component. The associated identifier of this vulnerability is VDB-220751.

- [https://github.com/Live-Hack-CVE/CVE-2015-10079](https://github.com/Live-Hack-CVE/CVE-2015-10079) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2015-10079.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2015-10079.svg)


## CVE-2015-2794
 The installation wizard in DotNetNuke (DNN) before 7.4.1 allows remote attackers to reinstall the application and gain SuperUser access via a direct request to Install/InstallWizard.aspx.

- [https://github.com/styx00/DNN_CVE-2015-2794](https://github.com/styx00/DNN_CVE-2015-2794) :  ![starts](https://img.shields.io/github/stars/styx00/DNN_CVE-2015-2794.svg) ![forks](https://img.shields.io/github/forks/styx00/DNN_CVE-2015-2794.svg)


## CVE-2015-0241
 The to_char function in PostgreSQL before 9.0.19, 9.1.x before 9.1.15, 9.2.x before 9.2.10, 9.3.x before 9.3.6, and 9.4.x before 9.4.1 allows remote authenticated users to cause a denial of service (crash) or possibly execute arbitrary code via a (1) large number of digits when processing a numeric formatting template, which triggers a buffer over-read, or (2) crafted timestamp formatting template, which triggers a buffer overflow.

- [https://github.com/bidimensional/pgtest](https://github.com/bidimensional/pgtest) :  ![starts](https://img.shields.io/github/stars/bidimensional/pgtest.svg) ![forks](https://img.shields.io/github/forks/bidimensional/pgtest.svg)


## CVE-2014-6195
 The (1) Java GUI and (2) Web GUI components in the IBM Tivoli Storage Manager (TSM) Backup-Archive client 5.4 and 5.5 before 5.5.4.4 on AIX, Linux, and Solaris; 5.4.x and 5.5.x on Windows and z/OS; 6.1 before 6.1.5.7 on z/OS; 6.1 and 6.2 before 6.2.5.2 on Windows, before 6.2.5.3 on AIX and Linux x86, and before 6.2.5.4 on Linux Z and Solaris; 6.3 before 6.3.2.1 on AIX, before 6.3.2.2 on Windows, and before 6.3.2.3 on Linux; 6.4 before 6.4.2.1; and 7.1 before 7.1.1 in IBM TSM for Mail, when the Data Protection for Lotus Domino component is used, allow local users to bypass authentication and restore a Domino database or transaction-log backup via unspecified vectors.

- [https://github.com/Live-Hack-CVE/CVE-2014-6195](https://github.com/Live-Hack-CVE/CVE-2014-6195) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2014-6195.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2014-6195.svg)


## CVE-2012-3287
 Poul-Henning Kamp md5crypt has insufficient algorithmic complexity and a consequently short runtime, which makes it easier for context-dependent attackers to discover cleartext passwords via a brute-force attack, as demonstrated by an attack using GPU hardware.

- [https://github.com/Live-Hack-CVE/CVE-2012-3287](https://github.com/Live-Hack-CVE/CVE-2012-3287) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2012-3287.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2012-3287.svg)

