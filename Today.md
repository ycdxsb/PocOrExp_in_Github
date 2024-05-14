# Update 2024-05-14
## CVE-2024-31771
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/restdone/CVE-2024-31771](https://github.com/restdone/CVE-2024-31771) :  ![starts](https://img.shields.io/github/stars/restdone/CVE-2024-31771.svg) ![forks](https://img.shields.io/github/forks/restdone/CVE-2024-31771.svg)


## CVE-2024-22774
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Gray-0men/CVE-2024-22774](https://github.com/Gray-0men/CVE-2024-22774) :  ![starts](https://img.shields.io/github/stars/Gray-0men/CVE-2024-22774.svg) ![forks](https://img.shields.io/github/forks/Gray-0men/CVE-2024-22774.svg)


## CVE-2024-3435
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/Voorivex/CVE-2024-34351](https://github.com/Voorivex/CVE-2024-34351) :  ![starts](https://img.shields.io/github/stars/Voorivex/CVE-2024-34351.svg) ![forks](https://img.shields.io/github/forks/Voorivex/CVE-2024-34351.svg)


## CVE-2024-3400
 A command injection as a result of arbitrary file creation vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall. Cloud NGFW, Panorama appliances, and Prisma Access are not impacted by this vulnerability.

- [https://github.com/andrelia-hacks/CVE-2024-3400](https://github.com/andrelia-hacks/CVE-2024-3400) :  ![starts](https://img.shields.io/github/stars/andrelia-hacks/CVE-2024-3400.svg) ![forks](https://img.shields.io/github/forks/andrelia-hacks/CVE-2024-3400.svg)


## CVE-2024-1561
 An issue was discovered in gradio-app/gradio, where the `/component_server` endpoint improperly allows the invocation of any method on a `Component` class with attacker-controlled arguments. Specifically, by exploiting the `move_resource_to_block_cache()` method of the `Block` class, an attacker can copy any file on the filesystem to a temporary directory and subsequently retrieve it. This vulnerability enables unauthorized local file read access, posing a significant risk especially when the application is exposed to the internet via `launch(share=True)`, thereby allowing remote attackers to read files on the host machine. Furthermore, gradio apps hosted on `huggingface.co` are also affected, potentially leading to the exposure of sensitive information such as API keys and credentials stored in environment variables.

- [https://github.com/DiabloHTB/Nuclei-Template-CVE-2024-1561](https://github.com/DiabloHTB/Nuclei-Template-CVE-2024-1561) :  ![starts](https://img.shields.io/github/stars/DiabloHTB/Nuclei-Template-CVE-2024-1561.svg) ![forks](https://img.shields.io/github/forks/DiabloHTB/Nuclei-Template-CVE-2024-1561.svg)


## CVE-2023-33733
 Reportlab up to v3.6.12 allows attackers to execute arbitrary code via supplying a crafted PDF file.

- [https://github.com/huyqa/CVE-2023-33733](https://github.com/huyqa/CVE-2023-33733) :  ![starts](https://img.shields.io/github/stars/huyqa/CVE-2023-33733.svg) ![forks](https://img.shields.io/github/forks/huyqa/CVE-2023-33733.svg)


## CVE-2020-17057
 Windows Win32k Elevation of Privilege Vulnerability

- [https://github.com/fengjixuchui/cve-2020-17057](https://github.com/fengjixuchui/cve-2020-17057) :  ![starts](https://img.shields.io/github/stars/fengjixuchui/cve-2020-17057.svg) ![forks](https://img.shields.io/github/forks/fengjixuchui/cve-2020-17057.svg)


## CVE-2020-1938
 When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the web application - processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

- [https://github.com/whatboxapp/GhostCat-LFI-exp](https://github.com/whatboxapp/GhostCat-LFI-exp) :  ![starts](https://img.shields.io/github/stars/whatboxapp/GhostCat-LFI-exp.svg) ![forks](https://img.shields.io/github/forks/whatboxapp/GhostCat-LFI-exp.svg)


## CVE-2018-10583
 An information disclosure vulnerability occurs when LibreOffice 6.0.3 and Apache OpenOffice Writer 4.1.5 automatically process and initiate an SMB connection embedded in a malicious file, as demonstrated by xlink:href=file://192.168.0.2/test.jpg within an office:document-content element in a .odt XML document.

- [https://github.com/octodi/CVE-2018-10583](https://github.com/octodi/CVE-2018-10583) :  ![starts](https://img.shields.io/github/stars/octodi/CVE-2018-10583.svg) ![forks](https://img.shields.io/github/forks/octodi/CVE-2018-10583.svg)

