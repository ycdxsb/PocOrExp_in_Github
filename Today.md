# Update 2025-02-18
## CVE-2025-24016
 Wazuh is a free and open source platform used for threat prevention, detection, and response. Starting in version 4.4.0 and prior to version 4.9.1, an unsafe deserialization vulnerability allows for remote code execution on Wazuh servers. DistributedAPI parameters are a serialized as JSON and deserialized using `as_wazuh_object` (in `framework/wazuh/core/cluster/common.py`). If an attacker manages to inject an unsanitized dictionary in DAPI request/response, they can forge an unhandled exception (`__unhandled_exc__`) to evaluate arbitrary python code. The vulnerability can be triggered by anybody with API access (compromised dashboard or Wazuh servers in the cluster) or, in certain configurations, even by a compromised agent. Version 4.9.1 contains a fix.

- [https://github.com/0xjessie21/CVE-2025-24016](https://github.com/0xjessie21/CVE-2025-24016) :  ![starts](https://img.shields.io/github/stars/0xjessie21/CVE-2025-24016.svg) ![forks](https://img.shields.io/github/forks/0xjessie21/CVE-2025-24016.svg)


## CVE-2024-48990
 Qualys discovered that needrestart, before version 3.8, allows local attackers to execute arbitrary code as root by tricking needrestart into running the Python interpreter with an attacker-controlled PYTHONPATH environment variable.

- [https://github.com/ten-ops/CVE-2024-48990_needrestart](https://github.com/ten-ops/CVE-2024-48990_needrestart) :  ![starts](https://img.shields.io/github/stars/ten-ops/CVE-2024-48990_needrestart.svg) ![forks](https://img.shields.io/github/forks/ten-ops/CVE-2024-48990_needrestart.svg)


## CVE-2024-42327
 A non-admin user account on the Zabbix frontend with the default User role, or with any other role that gives API access can exploit this vulnerability. An SQLi exists in the CUser class in the addRelatedObjects function, this function is being called from the CUser.get function which is available for every user who has API access.

- [https://github.com/godylockz/CVE-2024-42327](https://github.com/godylockz/CVE-2024-42327) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2024-42327.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2024-42327.svg)


## CVE-2024-5084
 The Hash Form – Drag & Drop Form Builder plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the 'file_upload_action' function in all versions up to, and including, 1.1.0. This makes it possible for unauthenticated attackers to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/ModeBrutal/CVE-2024-5084-Auto-Exploit](https://github.com/ModeBrutal/CVE-2024-5084-Auto-Exploit) :  ![starts](https://img.shields.io/github/stars/ModeBrutal/CVE-2024-5084-Auto-Exploit.svg) ![forks](https://img.shields.io/github/forks/ModeBrutal/CVE-2024-5084-Auto-Exploit.svg)


## CVE-2023-7028
 An issue has been discovered in GitLab CE/EE affecting all versions from 16.1 prior to 16.1.6, 16.2 prior to 16.2.9, 16.3 prior to 16.3.7, 16.4 prior to 16.4.5, 16.5 prior to 16.5.6, 16.6 prior to 16.6.4, and 16.7 prior to 16.7.2 in which user account password reset emails could be delivered to an unverified email address.

- [https://github.com/sariamubeen/CVE-2023-7028](https://github.com/sariamubeen/CVE-2023-7028) :  ![starts](https://img.shields.io/github/stars/sariamubeen/CVE-2023-7028.svg) ![forks](https://img.shields.io/github/forks/sariamubeen/CVE-2023-7028.svg)


## CVE-2021-44967
 A Remote Code Execution (RCE) vulnerabilty exists in LimeSurvey 5.2.4 via the upload and install plugins function, which could let a remote malicious user upload an arbitrary PHP code file.

- [https://github.com/godylockz/CVE-2021-44967](https://github.com/godylockz/CVE-2021-44967) :  ![starts](https://img.shields.io/github/stars/godylockz/CVE-2021-44967.svg) ![forks](https://img.shields.io/github/forks/godylockz/CVE-2021-44967.svg)


## CVE-2019-19609
 The Strapi framework before 3.0.0-beta.17.8 is vulnerable to Remote Code Execution in the Install and Uninstall Plugin components of the Admin panel, because it does not sanitize the plugin name, and attackers can inject arbitrary shell commands to be executed by the execa function.

- [https://github.com/abelsrzz/CVE-2019-18818_CVE-2019-19609](https://github.com/abelsrzz/CVE-2019-18818_CVE-2019-19609) :  ![starts](https://img.shields.io/github/stars/abelsrzz/CVE-2019-18818_CVE-2019-19609.svg) ![forks](https://img.shields.io/github/forks/abelsrzz/CVE-2019-18818_CVE-2019-19609.svg)


## CVE-2019-18818
 strapi before 3.0.0-beta.17.5 mishandles password resets within packages/strapi-admin/controllers/Auth.js and packages/strapi-plugin-users-permissions/controllers/Auth.js.

- [https://github.com/abelsrzz/CVE-2019-18818_CVE-2019-19609](https://github.com/abelsrzz/CVE-2019-18818_CVE-2019-19609) :  ![starts](https://img.shields.io/github/stars/abelsrzz/CVE-2019-18818_CVE-2019-19609.svg) ![forks](https://img.shields.io/github/forks/abelsrzz/CVE-2019-18818_CVE-2019-19609.svg)


## CVE-2012-1823
 sapi/cgi/cgi_main.c in PHP before 5.3.12 and 5.4.x before 5.4.2, when configured as a CGI script (aka php-cgi), does not properly handle query strings that lack an = (equals sign) character, which allows remote attackers to execute arbitrary code by placing command-line options in the query string, related to lack of skipping a certain php_getopt for the 'd' case.

- [https://github.com/JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web](https://github.com/JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web) :  ![starts](https://img.shields.io/github/stars/JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web.svg) ![forks](https://img.shields.io/github/forks/JasonHobs/CVE-2012-1823-exploit-for-https-user-password-web.svg)

