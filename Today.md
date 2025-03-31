# Update 2025-03-31
## CVE-2025-29927
 Next.js is a React framework for building full-stack web applications. Prior to 14.2.25 and 15.2.3, it is possible to bypass authorization checks within a Next.js application, if the authorization check occurs in middleware. If patching to a safe version is infeasible, it is recommend that you prevent external user requests which contain the x-middleware-subrequest header from reaching your Next.js application. This vulnerability is fixed in 14.2.25 and 15.2.3.

- [https://github.com/dante01yoon/CVE-2025-29927](https://github.com/dante01yoon/CVE-2025-29927) :  ![starts](https://img.shields.io/github/stars/dante01yoon/CVE-2025-29927.svg) ![forks](https://img.shields.io/github/forks/dante01yoon/CVE-2025-29927.svg)
- [https://github.com/w2hcorp/CVE-2025-29927-PoC](https://github.com/w2hcorp/CVE-2025-29927-PoC) :  ![starts](https://img.shields.io/github/stars/w2hcorp/CVE-2025-29927-PoC.svg) ![forks](https://img.shields.io/github/forks/w2hcorp/CVE-2025-29927-PoC.svg)


## CVE-2025-24071
 Exposure of sensitive information to an unauthorized actor in Windows File Explorer allows an unauthorized attacker to perform spoofing over a network.

- [https://github.com/cesarbtakeda/Windows-Explorer-CVE-2025-24071](https://github.com/cesarbtakeda/Windows-Explorer-CVE-2025-24071) :  ![starts](https://img.shields.io/github/stars/cesarbtakeda/Windows-Explorer-CVE-2025-24071.svg) ![forks](https://img.shields.io/github/forks/cesarbtakeda/Windows-Explorer-CVE-2025-24071.svg)


## CVE-2025-2857
*This only affects Firefox on Windows. Other operating systems are unaffected.* This vulnerability affects Firefox  136.0.4, Firefox ESR  128.8.1, and Firefox ESR  115.21.1.

- [https://github.com/ubisoftinc/CVE-2025-2857](https://github.com/ubisoftinc/CVE-2025-2857) :  ![starts](https://img.shields.io/github/stars/ubisoftinc/CVE-2025-2857.svg) ![forks](https://img.shields.io/github/forks/ubisoftinc/CVE-2025-2857.svg)


## CVE-2025-2266
 The Checkout Mestres do WP for WooCommerce plugin for WordPress is vulnerable to unauthorized modification of data that can lead to privilege escalation due to a missing capability check on the cwmpUpdateOptions() function in versions 8.6.5 to 8.7.5. This makes it possible for unauthenticated attackers to update arbitrary options on the WordPress site. This can be leveraged to update the default role for registration to administrator and enable user registration for attackers to gain administrative user access to a vulnerable site.

- [https://github.com/Nxploited/CVE-2025-2266](https://github.com/Nxploited/CVE-2025-2266) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2266.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2266.svg)


## CVE-2025-2249
 The SoJ SoundSlides plugin for WordPress is vulnerable to arbitrary file uploads due to missing file type validation in the soj_soundslides_options_subpanel() function in all versions up to, and including, 1.2.2. This makes it possible for authenticated attackers, with Contributor-level access and above, to upload arbitrary files on the affected site's server which may make remote code execution possible.

- [https://github.com/Nxploited/CVE-2025-2249](https://github.com/Nxploited/CVE-2025-2249) :  ![starts](https://img.shields.io/github/stars/Nxploited/CVE-2025-2249.svg) ![forks](https://img.shields.io/github/forks/Nxploited/CVE-2025-2249.svg)


## CVE-2024-25180
 An issue discovered in pdfmake 0.2.9 allows remote attackers to run arbitrary code via crafted POST request to the /pdf endpoint. NOTE: this is disputed because the behavior of the /pdf endpoint is intentional. The /pdf endpoint is only available after installing a test framework (that lives outside of the pdfmake applicaton). Anyone installing this is responsible for ensuring that it is only available to authorized testers.

- [https://github.com/dustblessnotdust/CVE-2024-25180](https://github.com/dustblessnotdust/CVE-2024-25180) :  ![starts](https://img.shields.io/github/stars/dustblessnotdust/CVE-2024-25180.svg) ![forks](https://img.shields.io/github/forks/dustblessnotdust/CVE-2024-25180.svg)


## CVE-2024-0406
 A flaw was discovered in the mholt/archiver package. This flaw allows an attacker to create a specially crafted tar file, which, when unpacked, may allow access to restricted files or directories. This issue can allow the creation or overwriting of files with the user's or application's privileges using the library.

- [https://github.com/veissa/Desires](https://github.com/veissa/Desires) :  ![starts](https://img.shields.io/github/stars/veissa/Desires.svg) ![forks](https://img.shields.io/github/forks/veissa/Desires.svg)


## CVE-2022-48150
 Shopware v5.5.10 was discovered to contain a cross-site scripting (XSS) vulnerability via the recovery/install/ URI.

- [https://github.com/SahilH4ck4you/-CVE-2022-48150](https://github.com/SahilH4ck4you/-CVE-2022-48150) :  ![starts](https://img.shields.io/github/stars/SahilH4ck4you/-CVE-2022-48150.svg) ![forks](https://img.shields.io/github/forks/SahilH4ck4you/-CVE-2022-48150.svg)


## CVE-2022-39299
 Passport-SAML is a SAML 2.0 authentication provider for Passport, the Node.js authentication library. A remote attacker may be able to bypass SAML authentication on a website using passport-saml. A successful attack requires that the attacker is in possession of an arbitrary IDP signed XML element. Depending on the IDP used, fully unauthenticated attacks (e.g without access to a valid user) might also be feasible if generation of a signed message can be triggered. Users should upgrade to passport-saml version 3.2.2 or newer. The issue was also present in the beta releases of `node-saml` before version 4.0.0-beta.5. If you cannot upgrade, disabling SAML authentication may be done as a workaround.

- [https://github.com/KaztoRay/CVE-2022-39299-Research](https://github.com/KaztoRay/CVE-2022-39299-Research) :  ![starts](https://img.shields.io/github/stars/KaztoRay/CVE-2022-39299-Research.svg) ![forks](https://img.shields.io/github/forks/KaztoRay/CVE-2022-39299-Research.svg)


## CVE-2020-11652
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class allows access to some methods that improperly sanitize paths. These methods allow arbitrary directory access to authenticated users.

- [https://github.com/Drew-Alleman/CVE-2020-11651](https://github.com/Drew-Alleman/CVE-2020-11651) :  ![starts](https://img.shields.io/github/stars/Drew-Alleman/CVE-2020-11651.svg) ![forks](https://img.shields.io/github/forks/Drew-Alleman/CVE-2020-11651.svg)


## CVE-2020-11651
 An issue was discovered in SaltStack Salt before 2019.2.4 and 3000 before 3000.2. The salt-master process ClearFuncs class does not properly validate method calls. This allows a remote user to access some methods without authentication. These methods can be used to retrieve user tokens from the salt master and/or run arbitrary commands on salt minions.

- [https://github.com/Drew-Alleman/CVE-2020-11651](https://github.com/Drew-Alleman/CVE-2020-11651) :  ![starts](https://img.shields.io/github/stars/Drew-Alleman/CVE-2020-11651.svg) ![forks](https://img.shields.io/github/forks/Drew-Alleman/CVE-2020-11651.svg)


## CVE-2018-6574
 Go before 1.8.7, Go 1.9.x before 1.9.4, and Go 1.10 pre-releases before Go 1.10rc2 allow "go get" remote command execution during source code build, by leveraging the gcc or clang plugin feature, because -fplugin= and -plugin= arguments were not blocked.

- [https://github.com/rootxjs/CVE-2018-6574](https://github.com/rootxjs/CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/rootxjs/CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/rootxjs/CVE-2018-6574.svg)
- [https://github.com/rootxjs/new-CVE-2018-6574](https://github.com/rootxjs/new-CVE-2018-6574) :  ![starts](https://img.shields.io/github/stars/rootxjs/new-CVE-2018-6574.svg) ![forks](https://img.shields.io/github/forks/rootxjs/new-CVE-2018-6574.svg)


## CVE-2018-6242
 Some NVIDIA Tegra mobile processors released prior to 2016 contain a buffer overflow vulnerability in BootROM Recovery Mode (RCM). An attacker with physical access to the device's USB and the ability to force the device to reboot into RCM could exploit the vulnerability to execute unverified code.

- [https://github.com/aditi2285/My-First-App](https://github.com/aditi2285/My-First-App) :  ![starts](https://img.shields.io/github/stars/aditi2285/My-First-App.svg) ![forks](https://img.shields.io/github/forks/aditi2285/My-First-App.svg)

