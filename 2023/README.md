## CVE-2023-22551
 The FTP (aka &quot;Implementation of a simple FTP client and server&quot;) project through 96c1a35 allows remote attackers to cause a denial of service (memory consumption) by engaging in client activity, such as establishing and then terminating a connection. This occurs because malloc is used but free is not.



- [https://github.com/Live-Hack-CVE/CVE-2023-22551](https://github.com/Live-Hack-CVE/CVE-2023-22551) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22551.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22551.svg)

## CVE-2023-22452
 kenny2automate is a Discord bot. In the web interface for server settings, form elements were generated with Discord channel IDs as part of input names. Prior to commit a947d7c, no validation was performed to ensure that the channel IDs submitted actually belonged to the server being configured. Thus anyone who has access to the channel ID they wish to change settings for and the server settings panel for any server could change settings for the requested channel no matter which server it belonged to. Commit a947d7c resolves the issue and has been deployed to the official instance of the bot. The only workaround that exists is to disable the web config entirely by changing it to run on localhost. Note that a workaround is only necessary for those who run their own instance of the bot.



- [https://github.com/Live-Hack-CVE/CVE-2023-22452](https://github.com/Live-Hack-CVE/CVE-2023-22452) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22452.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22452.svg)

## CVE-2023-22451
 Kiwi TCMS is an open source test management system. In version 11.6 and prior, when users register new accounts and/or change passwords, there is no validation in place which would prevent them from picking an easy to guess password. This issue is resolved by providing defaults for the `AUTH_PASSWORD_VALIDATORS` configuration setting. As of version 11.7, the password can&#8217;t be too similar to other personal information, must contain at least 10 characters, can&#8217;t be a commonly used password, and can&#8217;t be entirely numeric. As a workaround, an administrator may reset all passwords in Kiwi TCMS if they think a weak password may have been chosen.



- [https://github.com/Live-Hack-CVE/CVE-2023-22451](https://github.com/Live-Hack-CVE/CVE-2023-22451) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-22451.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-22451.svg)

## CVE-2023-0029
 A vulnerability was found in Multilaser RE708 RE1200R4GC-2T2R-V3_v3411b_MUL029B. It has been rated as problematic. This issue affects some unknown processing of the component Telnet Service. The manipulation leads to denial of service. The attack may be initiated remotely. The identifier VDB-217169 was assigned to this vulnerability.



- [https://github.com/Live-Hack-CVE/CVE-2023-0029](https://github.com/Live-Hack-CVE/CVE-2023-0029) :  ![starts](https://img.shields.io/github/stars/Live-Hack-CVE/CVE-2023-0029.svg) ![forks](https://img.shields.io/github/forks/Live-Hack-CVE/CVE-2023-0029.svg)
