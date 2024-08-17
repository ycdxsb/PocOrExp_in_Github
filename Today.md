# Update 2024-08-17
## CVE-2024-38077
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/BBD-YZZ/fyne-gui](https://github.com/BBD-YZZ/fyne-gui) :  ![starts](https://img.shields.io/github/stars/BBD-YZZ/fyne-gui.svg) ![forks](https://img.shields.io/github/forks/BBD-YZZ/fyne-gui.svg)
- [https://github.com/SecStarBot/CVE-2024-38077-POC](https://github.com/SecStarBot/CVE-2024-38077-POC) :  ![starts](https://img.shields.io/github/stars/SecStarBot/CVE-2024-38077-POC.svg) ![forks](https://img.shields.io/github/forks/SecStarBot/CVE-2024-38077-POC.svg)


## CVE-2024-38063
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/diegoalbuquerque/CVE-2024-38063](https://github.com/diegoalbuquerque/CVE-2024-38063) :  ![starts](https://img.shields.io/github/stars/diegoalbuquerque/CVE-2024-38063.svg) ![forks](https://img.shields.io/github/forks/diegoalbuquerque/CVE-2024-38063.svg)


## CVE-2024-21733
 Generation of Error Message Containing Sensitive Information vulnerability in Apache Tomcat.This issue affects Apache Tomcat: from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43. Users are recommended to upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue.

- [https://github.com/LtmThink/CVE-2024-21733](https://github.com/LtmThink/CVE-2024-21733) :  ![starts](https://img.shields.io/github/stars/LtmThink/CVE-2024-21733.svg) ![forks](https://img.shields.io/github/forks/LtmThink/CVE-2024-21733.svg)


## CVE-2024-4285
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/njmbb8/CVE-2024-42850](https://github.com/njmbb8/CVE-2024-42850) :  ![starts](https://img.shields.io/github/stars/njmbb8/CVE-2024-42850.svg) ![forks](https://img.shields.io/github/forks/njmbb8/CVE-2024-42850.svg)


## CVE-2024-4284
 A vulnerability in mintplex-labs/anything-llm allows for a denial of service (DoS) condition through the modification of a user's `id` attribute to a value of 0. This issue affects the current version of the software, with the latest commit id `57984fa85c31988b2eff429adfc654c46e0c342a`. By exploiting this vulnerability, an attacker, with manager or admin privileges, can render a chosen account completely inaccessible. The application's mechanism for suspending accounts does not provide a means to reverse this condition through the UI, leading to uncontrolled resource consumption. The vulnerability is introduced due to the lack of input validation and sanitization in the user modification endpoint and the middleware's token validation logic. This issue has been addressed in version 1.0.0 of the software.

- [https://github.com/njmbb8/CVE-2024-42849](https://github.com/njmbb8/CVE-2024-42849) :  ![starts](https://img.shields.io/github/stars/njmbb8/CVE-2024-42849.svg) ![forks](https://img.shields.io/github/forks/njmbb8/CVE-2024-42849.svg)


## CVE-2024-4275
 The Essential Addons for Elementor &#8211; Best Elementor Templates, Widgets, Kits &amp; WooCommerce Builders plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the plugin's Interactive Circle widget in all versions up to, and including, 5.9.19 due to insufficient input sanitization and output escaping on user supplied attributes. This makes it possible for authenticated attackers, with contributor-level access and above, to inject arbitrary web scripts in pages that will execute whenever a user accesses an injected page.

- [https://github.com/1s1ldur/CVE-2024-42758](https://github.com/1s1ldur/CVE-2024-42758) :  ![starts](https://img.shields.io/github/stars/1s1ldur/CVE-2024-42758.svg) ![forks](https://img.shields.io/github/forks/1s1ldur/CVE-2024-42758.svg)


## CVE-2024-1086
 A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation. The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT. We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

- [https://github.com/pl0xe/CVE-2024-1086](https://github.com/pl0xe/CVE-2024-1086) :  ![starts](https://img.shields.io/github/stars/pl0xe/CVE-2024-1086.svg) ![forks](https://img.shields.io/github/forks/pl0xe/CVE-2024-1086.svg)


## CVE-2023-27372
 SPIP before 4.2.1 allows Remote Code Execution via form values in the public area because serialization is mishandled. The fixed versions are 3.2.18, 4.0.10, 4.1.8, and 4.2.1.

- [https://github.com/1amthebest1/CVE-2023-27372](https://github.com/1amthebest1/CVE-2023-27372) :  ![starts](https://img.shields.io/github/stars/1amthebest1/CVE-2023-27372.svg) ![forks](https://img.shields.io/github/forks/1amthebest1/CVE-2023-27372.svg)


## CVE-2021-24807
 The Support Board WordPress plugin before 3.3.5 allows Authenticated (Agent+) users to perform Cross-Site Scripting attacks by placing a payload in the notes field, when an administrator or any authenticated user go to the chat the XSS will be automatically executed.

- [https://github.com/dldygnl/CVE-2021-24807](https://github.com/dldygnl/CVE-2021-24807) :  ![starts](https://img.shields.io/github/stars/dldygnl/CVE-2021-24807.svg) ![forks](https://img.shields.io/github/forks/dldygnl/CVE-2021-24807.svg)


## CVE-2021-24741
 The Support Board WordPress plugin before 3.3.4 does not escape multiple POST parameters (such as status_code, department, user_id, conversation_id, conversation_status_code, and recipient_id) before using them in SQL statements, leading to SQL injections which are exploitable by unauthenticated users.

- [https://github.com/dldygnl/CVE-2021-24741](https://github.com/dldygnl/CVE-2021-24741) :  ![starts](https://img.shields.io/github/stars/dldygnl/CVE-2021-24741.svg) ![forks](https://img.shields.io/github/forks/dldygnl/CVE-2021-24741.svg)


## CVE-2020-5902
 In BIG-IP versions 15.0.0-15.1.0.3, 14.1.0-14.1.2.5, 13.1.0-13.1.3.3, 12.1.0-12.1.5.1, and 11.6.1-11.6.5.1, the Traffic Management User Interface (TMUI), also referred to as the Configuration utility, has a Remote Code Execution (RCE) vulnerability in undisclosed pages.

- [https://github.com/flyopenair/CVE-2020-5902](https://github.com/flyopenair/CVE-2020-5902) :  ![starts](https://img.shields.io/github/stars/flyopenair/CVE-2020-5902.svg) ![forks](https://img.shields.io/github/forks/flyopenair/CVE-2020-5902.svg)


## CVE-2019-16113
 Bludit 3.9.2 allows remote code execution via bl-kernel/ajax/upload-images.php because PHP code can be entered with a .jpg file name, and then this PHP code can write other PHP code to a ../ pathname.

- [https://github.com/dldygnl/CVE-2019-16113](https://github.com/dldygnl/CVE-2019-16113) :  ![starts](https://img.shields.io/github/stars/dldygnl/CVE-2019-16113.svg) ![forks](https://img.shields.io/github/forks/dldygnl/CVE-2019-16113.svg)

