# Update 2023-06-18
## CVE-2023-34830
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/leekenghwa/CVE-2023-34830---Reflected-XSS-found-in-I-doit-Open-v24-and-below](https://github.com/leekenghwa/CVE-2023-34830---Reflected-XSS-found-in-I-doit-Open-v24-and-below) :  ![starts](https://img.shields.io/github/stars/leekenghwa/CVE-2023-34830---Reflected-XSS-found-in-I-doit-Open-v24-and-below.svg) ![forks](https://img.shields.io/github/forks/leekenghwa/CVE-2023-34830---Reflected-XSS-found-in-I-doit-Open-v24-and-below.svg)


## CVE-2023-34600
 ** RESERVED ** This candidate has been reserved by an organization or individual that will use it when announcing a new security problem. When the candidate has been publicized, the details for this candidate will be provided.

- [https://github.com/costacoco/Adiscon](https://github.com/costacoco/Adiscon) :  ![starts](https://img.shields.io/github/stars/costacoco/Adiscon.svg) ![forks](https://img.shields.io/github/forks/costacoco/Adiscon.svg)


## CVE-2023-34362
 In Progress MOVEit Transfer before 2021.0.6 (13.0.6), 2021.1.4 (13.1.4), 2022.0.4 (14.0.4), 2022.1.5 (14.1.5), and 2023.0.1 (15.0.1), a SQL injection vulnerability has been found in the MOVEit Transfer web application that could allow an unauthenticated attacker to gain access to MOVEit Transfer's database. Depending on the database engine being used (MySQL, Microsoft SQL Server, or Azure SQL), an attacker may be able to infer information about the structure and contents of the database, and execute SQL statements that alter or delete database elements. NOTE: this is exploited in the wild in May and June 2023; exploitation of unpatched systems can occur via HTTP or HTTPS. All versions (e.g., 2020.0 and 2019x) before the five explicitly mentioned versions are affected, including older unsupported versions.

- [https://github.com/hheeyywweellccoommee/CVE-2023-34362-zcial](https://github.com/hheeyywweellccoommee/CVE-2023-34362-zcial) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2023-34362-zcial.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2023-34362-zcial.svg)


## CVE-2023-30845
 ESPv2 is a service proxy that provides API management capabilities using Google Service Infrastructure. ESPv2 2.20.0 through 2.42.0 contains an authentication bypass vulnerability. API clients can craft a malicious `X-HTTP-Method-Override` header value to bypass JWT authentication in specific cases. ESPv2 allows malicious requests to bypass authentication if both the conditions are true: The requested HTTP method is **not** in the API service definition (OpenAPI spec or gRPC `google.api.http` proto annotations, and the specified `X-HTTP-Method-Override` is a valid HTTP method in the API service definition. ESPv2 will forward the request to your backend without checking the JWT. Attackers can craft requests with a malicious `X-HTTP-Method-Override` value that allows them to bypass specifying JWTs. Restricting API access with API keys works as intended and is not affected by this vulnerability. Upgrade deployments to release v2.43.0 or higher to receive a patch. This release ensures that JWT authentication occurs, even when the caller specifies `x-http-method-override`. `x-http-method-override` is still supported by v2.43.0+. API clients can continue sending this header to ESPv2.

- [https://github.com/jayluxferro/ESPv2](https://github.com/jayluxferro/ESPv2) :  ![starts](https://img.shields.io/github/stars/jayluxferro/ESPv2.svg) ![forks](https://img.shields.io/github/forks/jayluxferro/ESPv2.svg)


## CVE-2023-24078
 Real Time Logic FuguHub v8.1 and earlier was discovered to contain a remote code execution (RCE) vulnerability via the component /FuguHub/cmsdocs/.

- [https://github.com/overgrowncarrot1/CVE-2023-24078](https://github.com/overgrowncarrot1/CVE-2023-24078) :  ![starts](https://img.shields.io/github/stars/overgrowncarrot1/CVE-2023-24078.svg) ![forks](https://img.shields.io/github/forks/overgrowncarrot1/CVE-2023-24078.svg)


## CVE-2023-23752
 An issue was discovered in Joomla! 4.0.0 through 4.2.7. An improper access check allows unauthorized access to webservice endpoints.

- [https://github.com/Sweelg/CVE-2023-23752](https://github.com/Sweelg/CVE-2023-23752) :  ![starts](https://img.shields.io/github/stars/Sweelg/CVE-2023-23752.svg) ![forks](https://img.shields.io/github/forks/Sweelg/CVE-2023-23752.svg)


## CVE-2023-23333
 There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.

- [https://github.com/Mr-xn/CVE-2023-23333](https://github.com/Mr-xn/CVE-2023-23333) :  ![starts](https://img.shields.io/github/stars/Mr-xn/CVE-2023-23333.svg) ![forks](https://img.shields.io/github/forks/Mr-xn/CVE-2023-23333.svg)


## CVE-2022-31813
 Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on the origin server/application.

- [https://github.com/hackingyseguridad/curl](https://github.com/hackingyseguridad/curl) :  ![starts](https://img.shields.io/github/stars/hackingyseguridad/curl.svg) ![forks](https://img.shields.io/github/forks/hackingyseguridad/curl.svg)


## CVE-2022-30525
 A OS command injection vulnerability in the CGI program of Zyxel USG FLEX 100(W) firmware versions 5.00 through 5.21 Patch 1, USG FLEX 200 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 500 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 700 firmware versions 5.00 through 5.21 Patch 1, USG FLEX 50(W) firmware versions 5.10 through 5.21 Patch 1, USG20(W)-VPN firmware versions 5.10 through 5.21 Patch 1, ATP series firmware versions 5.10 through 5.21 Patch 1, VPN series firmware versions 4.60 through 5.21 Patch 1, which could allow an attacker to modify specific files and then execute some OS commands on a vulnerable device.

- [https://github.com/savior-only/CVE-2022-30525](https://github.com/savior-only/CVE-2022-30525) :  ![starts](https://img.shields.io/github/stars/savior-only/CVE-2022-30525.svg) ![forks](https://img.shields.io/github/forks/savior-only/CVE-2022-30525.svg)


## CVE-2018-1160
 Netatalk before 3.1.12 is vulnerable to an out of bounds write in dsi_opensess.c. This is due to lack of bounds checking on attacker controlled data. A remote unauthenticated attacker can leverage this vulnerability to achieve arbitrary code execution.

- [https://github.com/hheeyywweellccoommee/CVE-2018-1160-kxdmt](https://github.com/hheeyywweellccoommee/CVE-2018-1160-kxdmt) :  ![starts](https://img.shields.io/github/stars/hheeyywweellccoommee/CVE-2018-1160-kxdmt.svg) ![forks](https://img.shields.io/github/forks/hheeyywweellccoommee/CVE-2018-1160-kxdmt.svg)


## CVE-2017-17485
 FasterXML jackson-databind through 2.8.10 and 2.9.x through 2.9.3 allows unauthenticated remote code execution because of an incomplete fix for the CVE-2017-7525 deserialization flaw. This is exploitable by sending maliciously crafted JSON input to the readValue method of the ObjectMapper, bypassing a blacklist that is ineffective if the Spring libraries are available in the classpath.

- [https://github.com/rootsecurity/Jackson-CVE-2017-17485](https://github.com/rootsecurity/Jackson-CVE-2017-17485) :  ![starts](https://img.shields.io/github/stars/rootsecurity/Jackson-CVE-2017-17485.svg) ![forks](https://img.shields.io/github/forks/rootsecurity/Jackson-CVE-2017-17485.svg)


## CVE-2014-4322
 drivers/misc/qseecom.c in the QSEECOM driver for the Linux kernel 3.x, as used in Qualcomm Innovation Center (QuIC) Android contributions for MSM devices and other products, does not validate certain offset, length, and base values within an ioctl call, which allows attackers to gain privileges or cause a denial of service (memory corruption) via a crafted application.

- [https://github.com/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege](https://github.com/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege) :  ![starts](https://img.shields.io/github/stars/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege.svg) ![forks](https://img.shields.io/github/forks/koozxcv/CVE-2014-7911-CVE-2014-4322_get_root_privilege.svg)
- [https://github.com/askk/CVE-2014-4322_adaptation](https://github.com/askk/CVE-2014-4322_adaptation) :  ![starts](https://img.shields.io/github/stars/askk/CVE-2014-4322_adaptation.svg) ![forks](https://img.shields.io/github/forks/askk/CVE-2014-4322_adaptation.svg)

