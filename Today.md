# Update 2026-01-15
## CVE-2026-22804
 Termix is a web-based server management platform with SSH terminal, tunneling, and file editing capabilities. From 1.7.0 to 1.9.0, Stored Cross-Site Scripting (XSS) vulnerability exists in the Termix File Manager component. The application fails to sanitize SVG file content before rendering it. This allows an attacker who has compromised a managed SSH server to plant a malicious file, which, when previewed by the Termix user, executes arbitrary JavaScript in the context of the application. The vulnerability is located in src/ui/desktop/apps/file-manager/components/FileViewer.tsx. This vulnerability is fixed in 1.10.0.

- [https://github.com/ThemeHackers/CVE-2026-22804](https://github.com/ThemeHackers/CVE-2026-22804) :  ![starts](https://img.shields.io/github/stars/ThemeHackers/CVE-2026-22804.svg) ![forks](https://img.shields.io/github/forks/ThemeHackers/CVE-2026-22804.svg)


## CVE-2026-22241
 The Open eClass platform (formerly known as GUnet eClass) is a complete course management system. Prior to version 4.2, an arbitrary file upload vulnerability in the theme import functionality enables an attacker with administrative privileges to upload arbitrary files on the server's file system. The main cause of the issue is that no validation or sanitization of the file's present inside the zip archive. This leads to remote code execution on the web server. Version 4.2 patches the issue.

- [https://github.com/Ashifcoder/CVE-2026-22241](https://github.com/Ashifcoder/CVE-2026-22241) :  ![starts](https://img.shields.io/github/stars/Ashifcoder/CVE-2026-22241.svg) ![forks](https://img.shields.io/github/forks/Ashifcoder/CVE-2026-22241.svg)


## CVE-2025-66698
 An issue in Semantic machines v5.4.8 allows attackers to bypass authentication via sending a crafted HTTP request to various API endpoints.

- [https://github.com/Perunchess/CVE-2025-66698](https://github.com/Perunchess/CVE-2025-66698) :  ![starts](https://img.shields.io/github/stars/Perunchess/CVE-2025-66698.svg) ![forks](https://img.shields.io/github/forks/Perunchess/CVE-2025-66698.svg)


## CVE-2025-66478
 This CVE is a duplicate of CVE-2025-55182.

- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-realworld-calcom-yarn-monorepo.svg)
- [https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs](https://github.com/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs) :  ![starts](https://img.shields.io/github/stars/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg) ![forks](https://img.shields.io/github/forks/react2shell-repo-menagerie/CVE-2025-66478-single-nextjs-yarn-zero-installs.svg)


## CVE-2025-64155
 An improper neutralization of special elements used in an os command ('os command injection') vulnerability in Fortinet FortiSIEM 7.4.0, FortiSIEM 7.3.0 through 7.3.4, FortiSIEM 7.1.0 through 7.1.8, FortiSIEM 7.0.0 through 7.0.4, FortiSIEM 6.7.0 through 6.7.10 may allow an attacker to execute unauthorized code or commands via  crafted TCP requests.

- [https://github.com/horizon3ai/CVE-2025-64155](https://github.com/horizon3ai/CVE-2025-64155) :  ![starts](https://img.shields.io/github/stars/horizon3ai/CVE-2025-64155.svg) ![forks](https://img.shields.io/github/forks/horizon3ai/CVE-2025-64155.svg)


## CVE-2025-59057
 React Router is a router for React. In @remix-run/react versions 1.15.0 through 2.17.0. and react-router versions 7.0.0 through 7.8.2, a XSS vulnerability exists in in React Router's meta()/Meta APIs in Framework Mode when generating script:ld+json tags which could allow arbitrary JavaScript execution during SSR if untrusted content is used to generate the tag. There is no impact if the application is being used in Declarative Mode (BrowserRouter) or Data Mode (createBrowserRouter/RouterProvider). This issue has been patched in @remix-run/react version 2.17.1 and react-router version 7.9.0.

- [https://github.com/boroeurnprach/CVE-2025-59057-PoC](https://github.com/boroeurnprach/CVE-2025-59057-PoC) :  ![starts](https://img.shields.io/github/stars/boroeurnprach/CVE-2025-59057-PoC.svg) ![forks](https://img.shields.io/github/forks/boroeurnprach/CVE-2025-59057-PoC.svg)


## CVE-2025-55462
 A CORS misconfiguration in Eramba Community and Enterprise Editions v3.26.0 allows an attacker-controlled Origin header to be reflected in the Access-Control-Allow-Origin response along with Access-Control-Allow-Credentials: true. This permits malicious third-party websites to perform authenticated cross-origin requests against the Eramba API, including endpoints like /system-api/login and /system-api/user/me. The response includes sensitive user session data (ID, name, email, access groups), which is accessible to the attacker's JavaScript. This flaw enables full session hijack and data exfiltration without user interaction. Eramba versions 3.23.3 and earlier were tested and appear unaffected. The vulnerability is present in default installations, requiring no custom configuration.

- [https://github.com/sibikrish001/CVE-2025-55462](https://github.com/sibikrish001/CVE-2025-55462) :  ![starts](https://img.shields.io/github/stars/sibikrish001/CVE-2025-55462.svg) ![forks](https://img.shields.io/github/forks/sibikrish001/CVE-2025-55462.svg)


## CVE-2025-55182
 A pre-authentication remote code execution vulnerability exists in React Server Components versions 19.0.0, 19.1.0, 19.1.1, and 19.2.0 including the following packages: react-server-dom-parcel, react-server-dom-turbopack, and react-server-dom-webpack. The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints.

- [https://github.com/oscarmine/R2SAE](https://github.com/oscarmine/R2SAE) :  ![starts](https://img.shields.io/github/stars/oscarmine/R2SAE.svg) ![forks](https://img.shields.io/github/forks/oscarmine/R2SAE.svg)


## CVE-2025-53136
 Exposure of sensitive information to an unauthorized actor in Windows NT OS Kernel allows an authorized attacker to disclose information locally.

- [https://github.com/nu1lptr0/CVE-2025-53136](https://github.com/nu1lptr0/CVE-2025-53136) :  ![starts](https://img.shields.io/github/stars/nu1lptr0/CVE-2025-53136.svg) ![forks](https://img.shields.io/github/forks/nu1lptr0/CVE-2025-53136.svg)


## CVE-2025-43529
 A use-after-free issue was addressed with improved memory management. This issue is fixed in watchOS 26.2, Safari 26.2, iOS 18.7.3 and iPadOS 18.7.3, iOS 26.2 and iPadOS 26.2, macOS Tahoe 26.2, visionOS 26.2, tvOS 26.2. Processing maliciously crafted web content may lead to arbitrary code execution. Apple is aware of a report that this issue may have been exploited in an extremely sophisticated attack against specific targeted individuals on versions of iOS before iOS 26. CVE-2025-14174 was also issued in response to this report.

- [https://github.com/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis](https://github.com/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis) :  ![starts](https://img.shields.io/github/stars/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis.svg)


## CVE-2025-32463
 Sudo before 1.9.17p1 allows local users to obtain root access because /etc/nsswitch.conf from a user-controlled directory is used with the --chroot option.

- [https://github.com/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities](https://github.com/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities.svg)


## CVE-2025-32462
 Sudo before 1.9.17p1, when used with a sudoers file that specifies a host that is neither the current host nor ALL, allows listed users to execute commands on unintended machines.

- [https://github.com/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities](https://github.com/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities) :  ![starts](https://img.shields.io/github/stars/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities.svg) ![forks](https://img.shields.io/github/forks/lakshan-sameera/CVE-2025-32462-and-CVE-2025-32463---Critical-Sudo-Vulnerabilities.svg)


## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Starting in version 1.11.4 and prior to versions 12.3.5, 13.5.9, 14.2.25, and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 12.3.5, 13.5.9, 14.2.25, and 15.2.3.

- [https://github.com/maronnjapan/claude-create-CVE-2025-29927](https://github.com/maronnjapan/claude-create-CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/maronnjapan/claude-create-CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/maronnjapan/claude-create-CVE-2025-29927.svg)


## CVE-2025-14847
 Mismatched length fields in Zlib compressed protocol headers may allow a read of uninitialized heap memory by an unauthenticated client. This issue affects all MongoDB Server v7.0 prior to 7.0.28 versions, MongoDB Server v8.0 versions prior to 8.0.17, MongoDB Server v8.2 versions prior to 8.2.3, MongoDB Server v6.0 versions prior to 6.0.27, MongoDB Server v5.0 versions prior to 5.0.32, MongoDB Server v4.4 versions prior to 4.4.30, MongoDB Server v4.2 versions greater than or equal to 4.2.0, MongoDB Server v4.0 versions greater than or equal to 4.0.0, and MongoDB Server v3.6 versions greater than or equal to 3.6.0.

- [https://github.com/peakcyber-security/CVE-2025-14847](https://github.com/peakcyber-security/CVE-2025-14847) :  ![starts](https://img.shields.io/github/stars/peakcyber-security/CVE-2025-14847.svg) ![forks](https://img.shields.io/github/forks/peakcyber-security/CVE-2025-14847.svg)
- [https://github.com/alexcyberx/CVE-2025-14847_Expolit](https://github.com/alexcyberx/CVE-2025-14847_Expolit) :  ![starts](https://img.shields.io/github/stars/alexcyberx/CVE-2025-14847_Expolit.svg) ![forks](https://img.shields.io/github/forks/alexcyberx/CVE-2025-14847_Expolit.svg)
- [https://github.com/AmadoBatista/mongobleed](https://github.com/AmadoBatista/mongobleed) :  ![starts](https://img.shields.io/github/stars/AmadoBatista/mongobleed.svg) ![forks](https://img.shields.io/github/forks/AmadoBatista/mongobleed.svg)


## CVE-2025-14174
 Out of bounds memory access in ANGLE in Google Chrome on Mac prior to 143.0.7499.110 allowed a remote attacker to perform out of bounds memory access via a crafted HTML page. (Chromium security severity: High)

- [https://github.com/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis](https://github.com/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis) :  ![starts](https://img.shields.io/github/stars/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis.svg) ![forks](https://img.shields.io/github/forks/zeroxjf/WebKit-UAF-ANGLE-OOB-Analysis.svg)
- [https://github.com/houseofint3/CVE-2025-14174-analysis](https://github.com/houseofint3/CVE-2025-14174-analysis) :  ![starts](https://img.shields.io/github/stars/houseofint3/CVE-2025-14174-analysis.svg) ![forks](https://img.shields.io/github/forks/houseofint3/CVE-2025-14174-analysis.svg)


## CVE-2025-14172
 The WP Page Permalink Extension plugin for WordPress is vulnerable to Missing Authorization in all versions up to, and including, 1.5.4. This is due to missing authorization checks on the `cwpp_trigger_flush_rewrite_rules` function hooked to `wp_ajax_cwpp_trigger_flush_rewrite_rules`. This makes it possible for authenticated attackers, with Subscriber-level access and above, to flush the site's rewrite rules via the `action` parameter.

- [https://github.com/RootHarpy/CVE-2025-14172-Nuclei-Template](https://github.com/RootHarpy/CVE-2025-14172-Nuclei-Template) :  ![starts](https://img.shields.io/github/stars/RootHarpy/CVE-2025-14172-Nuclei-Template.svg) ![forks](https://img.shields.io/github/forks/RootHarpy/CVE-2025-14172-Nuclei-Template.svg)


## CVE-2025-9435
 Zohocorp ManageEngine ADManager Plus versions below 7230 are vulnerable to Path Traversal in the User Management module

- [https://github.com/passtheticket/CVE-2025-9435](https://github.com/passtheticket/CVE-2025-9435) :  ![starts](https://img.shields.io/github/stars/passtheticket/CVE-2025-9435.svg) ![forks](https://img.shields.io/github/forks/passtheticket/CVE-2025-9435.svg)


## CVE-2025-6739
 The WPQuiz plugin for WordPress is vulnerable to SQL Injection via the 'id' attribute of the 'wpquiz' shortcode in all versions up to, and including, 0.4.2 due to insufficient escaping on the user supplied parameter and lack of sufficient preparation on the existing SQL query.  This makes it possible for authenticated attackers, with Contributor-level access and above, to append additional SQL queries into already existing queries that can be used to extract sensitive information from the database.

- [https://github.com/rupeshsurve04/CVE-2025-67399](https://github.com/rupeshsurve04/CVE-2025-67399) :  ![starts](https://img.shields.io/github/stars/rupeshsurve04/CVE-2025-67399.svg) ![forks](https://img.shields.io/github/forks/rupeshsurve04/CVE-2025-67399.svg)


## CVE-2024-21762
 A out-of-bounds write in Fortinet FortiOS versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.6, 7.0.0 through 7.0.13, 6.4.0 through 6.4.14, 6.2.0 through 6.2.15, 6.0.0 through 6.0.17, FortiProxy versions 7.4.0 through 7.4.2, 7.2.0 through 7.2.8, 7.0.0 through 7.0.14, 2.0.0 through 2.0.13, 1.2.0 through 1.2.13, 1.1.0 through 1.1.6, 1.0.0 through 1.0.7 allows attacker to execute unauthorized code or commands via specifically crafted requests

- [https://github.com/0x13-ByteZer0/CVE-2024-21762](https://github.com/0x13-ByteZer0/CVE-2024-21762) :  ![starts](https://img.shields.io/github/stars/0x13-ByteZer0/CVE-2024-21762.svg) ![forks](https://img.shields.io/github/forks/0x13-ByteZer0/CVE-2024-21762.svg)


## CVE-2024-3094
Through a series of complex obfuscations, the liblzma build process extracts a prebuilt object file from a disguised test file existing in the source code, which is then used to modify specific functions in the liblzma code. This results in a modified liblzma library that can be used by any software linked against this library, intercepting and modifying the data interaction with this library.

- [https://github.com/encikayelwhitehat-glitch/CVE-2024-3094](https://github.com/encikayelwhitehat-glitch/CVE-2024-3094) :  ![starts](https://img.shields.io/github/stars/encikayelwhitehat-glitch/CVE-2024-3094.svg) ![forks](https://img.shields.io/github/forks/encikayelwhitehat-glitch/CVE-2024-3094.svg)


## CVE-2024-0692
 The SolarWinds Security Event Manager was susceptible to Remote Code Execution Vulnerability. This vulnerability allows an unauthenticated user to abuse SolarWinds’ service, resulting in remote code execution.

- [https://github.com/machevalia/CVE-2024-0692-SolarWinds-SEM-RCE](https://github.com/machevalia/CVE-2024-0692-SolarWinds-SEM-RCE) :  ![starts](https://img.shields.io/github/stars/machevalia/CVE-2024-0692-SolarWinds-SEM-RCE.svg) ![forks](https://img.shields.io/github/forks/machevalia/CVE-2024-0692-SolarWinds-SEM-RCE.svg)


## CVE-2024-0670
 Privilege escalation in windows agent plugin in Checkmk before 2.2.0p23, 2.1.0p40 and 2.0.0 (EOL) allows local user to escalate privileges

- [https://github.com/tralsesec/CVE-2024-0670](https://github.com/tralsesec/CVE-2024-0670) :  ![starts](https://img.shields.io/github/stars/tralsesec/CVE-2024-0670.svg) ![forks](https://img.shields.io/github/forks/tralsesec/CVE-2024-0670.svg)


## CVE-2024-0044
 In createSessionInternal of PackageInstallerService.java, there is a possible run-as any app due to improper input validation. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.

- [https://github.com/ronin0x1/CVE-2024-0044](https://github.com/ronin0x1/CVE-2024-0044) :  ![starts](https://img.shields.io/github/stars/ronin0x1/CVE-2024-0044.svg) ![forks](https://img.shields.io/github/forks/ronin0x1/CVE-2024-0044.svg)


## CVE-2023-4220
 Unrestricted file upload in big file upload functionality in `/main/inc/lib/javascript/bigupload/inc/bigUpload.php` in Chamilo LMS = v1.11.24 allows unauthenticated attackers to perform stored cross-site scripting attacks and obtain remote code execution via uploading of web shell.

- [https://github.com/Least-Significant-Bit/CVE-2023-4220](https://github.com/Least-Significant-Bit/CVE-2023-4220) :  ![starts](https://img.shields.io/github/stars/Least-Significant-Bit/CVE-2023-4220.svg) ![forks](https://img.shields.io/github/forks/Least-Significant-Bit/CVE-2023-4220.svg)


## CVE-2022-22965
 A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

- [https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis](https://github.com/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis) :  ![starts](https://img.shields.io/github/stars/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg) ![forks](https://img.shields.io/github/forks/Shakur1314/CVE-2022-22965-Spring4Shell-Security-Operations-Analysis.svg)


## CVE-2022-3294
 Users may have access to secure endpoints in the control plane network. Kubernetes clusters are only affected if an untrusted user can modify Node objects and send proxy requests to them. Kubernetes supports node proxying, which allows clients of kube-apiserver to access endpoints of a Kubelet to establish connections to Pods, retrieve container logs, and more. While Kubernetes already validates the proxying address for Nodes, a bug in kube-apiserver made it possible to bypass this validation. Bypassing this validation could allow authenticated requests destined for Nodes to to the API server's private network.

- [https://github.com/arbaaz29/CVE-2022-3294](https://github.com/arbaaz29/CVE-2022-3294) :  ![starts](https://img.shields.io/github/stars/arbaaz29/CVE-2022-3294.svg) ![forks](https://img.shields.io/github/forks/arbaaz29/CVE-2022-3294.svg)


## CVE-2018-4280
 A memory corruption issue was addressed with improved memory handling. This issue affected versions prior to iOS 11.4.1, macOS High Sierra 10.13.6, tvOS 11.4.1, watchOS 4.3.2.

- [https://github.com/BrandonAzad/blanket](https://github.com/BrandonAzad/blanket) :  ![starts](https://img.shields.io/github/stars/BrandonAzad/blanket.svg) ![forks](https://img.shields.io/github/forks/BrandonAzad/blanket.svg)


## CVE-2016-7617
 An issue was discovered in certain Apple products. macOS before 10.12.2 is affected. The issue involves the "Bluetooth" component. It allows attackers to execute arbitrary code in a privileged context or cause a denial of service (type confusion) via a crafted app.

- [https://github.com/BrandonAzad/physmem](https://github.com/BrandonAzad/physmem) :  ![starts](https://img.shields.io/github/stars/BrandonAzad/physmem.svg) ![forks](https://img.shields.io/github/forks/BrandonAzad/physmem.svg)


## CVE-2016-1828
 The kernel in Apple iOS before 9.3.2, OS X before 10.11.5, tvOS before 9.2.1, and watchOS before 2.2.1 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app, a different vulnerability than CVE-2016-1827, CVE-2016-1829, and CVE-2016-1830.

- [https://github.com/BrandonAzad/rootsh](https://github.com/BrandonAzad/rootsh) :  ![starts](https://img.shields.io/github/stars/BrandonAzad/rootsh.svg) ![forks](https://img.shields.io/github/forks/BrandonAzad/rootsh.svg)


## CVE-2016-1825
 IOHIDFamily in Apple OS X before 10.11.5 allows attackers to execute arbitrary code in a privileged context or cause a denial of service (memory corruption) via a crafted app.

- [https://github.com/BrandonAzad/physmem](https://github.com/BrandonAzad/physmem) :  ![starts](https://img.shields.io/github/stars/BrandonAzad/physmem.svg) ![forks](https://img.shields.io/github/forks/BrandonAzad/physmem.svg)

