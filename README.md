# Security Guide for Developers
- [Really Important stuff](#really-important-stuff)
- [General best practices](#general-best-practices)
  - [Development Process](#development-process)
  - [Application Design](#application-design)
  - [General protection](#general-protection)
  - [Testing](#testing)
  - [Running Application](#running-application)
  - [Data protection](#data-protection)
- [Application design](#application-design)
  - [Cookies](#cookies)
  - [Validation](#validation)
  - [Error Handling and Logging](#error-handling-and-logging)
  - [Authentication and Authorisation](#authentication--authorisation)
  - [Session Management](#session-management)
  - [Integration](#integration)
  - [File uploads](#file-uploads)
  - [Communication security](#communication-security)
- [Automated security testing](#automated-security-testing)
  - [NodeJS dependency security testing - Snyk](#nodejs-security-testing)
  - [Scala dependency security testing -  SBT Dependency Check](#scala-security-testing)
  - [Java dependency security testing](#java-security-testing)  
- [Resources](#useful-resources-and-books)

# Really important stuff!
- don’t put live data on any local device unless it has been signed off for such usage
- only access live / sensitive data under strict guidance (each service should have rules around its usage)
- understand the policies around where you should store your source code. NEVER put information such as passwords, API Keys or IP addresses in code repositories, even private ones.

# General best practices

## Development process
- security should be part of the agile delivery process and be applied per story
- use the [OWASP Security Testing Framework](https://www.owasp.org/index.php/The_OWASP_Testing_Framework) for a checklist
- enforce [protected branches](https://github.com/blog/2051-protected-branches-and-required-status-checks)
- enforce reviews via [pull requests](https://help.github.com/articles/using-pull-requests/)
- require [signed commits](https://help.github.com/articles/signing-commits-using-gpg/)
- have a well defined, understood and enforced peer review process
- ensure you have fast, repeatable deploys with automated testing
- monitor for security advisories and patches and update when necessary

## Application design

- favour simple systems; they are easier to secure
- adhere to the principles of [clean code](https://www.amazon.co.uk/Clean-Code-Handbook-Software-Craftsmanship/dp/0132350882) - this makes applications easier to understand
- consider [design by contract](https://en.wikipedia.org/wiki/Design_by_contract). [Preconditions](https://en.wikipedia.org/wiki/Precondition) set input constraints, [postconditions](https://en.wikipedia.org/wiki/Postcondition) what must be true; test against these
- reduce the attack surface by removing unnecessary code / libraries  endpoints, remove demo enabling code, default passwords etc.
- minimise integrations, understand and protect against compromised 3rd parties (e.g. a script sourced from an untrusted 3rd party could be malicious) 
- favour small components with a clear, [single responsibility](https://blog.8thlight.com/uncle-bob/2014/05/08/SingleReponsibilityPrinciple.html)
- favour using established libraries and frameworks over rolling your own. However, import only trustworthy software and always verify its integrity
- avoid the use of shared variables / [globals](http://programmers.stackexchange.com/questions/148108/why-is-global-state-so-evil)
- prefer [immutability](http://miles.no/blogg/why-care-about-functional-programming-part-1-immutability)
- avoid nulls by using [Option](https://en.wikipedia.org/wiki/Option_type) e.g. [Scala Option](http://danielwestheide.com/blog/2012/12/19/the-neophytes-guide-to-scala-part-5-the-option-type.html) and [Java Optional](http://onelineatatime.io/optional-guava-and-java-8/)

## General protection

- be careful using &lt;script src&gt; unless you have complete control over the script that is loaded
- if submitting a form modifies data or stage, use POST not GET
- avoid [SQL injection](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet) / javascript injection by ensuring all queries are [parameterised](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet) (and / or use e.g. an [ORM](https://en.wikipedia.org/wiki/Object-relational_mapping), [Active Record](http://www.martinfowler.com/eaaCatalog/activeRecord.html))
- protect against cross site scripting [(XSS)](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) by escaping / sanitising untrusted data using a standard security encoding library. Also consider using [Content Security Policy] (https://w3c.github.io/webappsec-csp/2/) headers to whitelist assets a page can load
- protect against cross site request forgery [(CSRF)](https://www.owasp.org/index.php/Cross-Site_Request_Forgery_(CSRF)) which target state-changing requests. Check standard headers to verify the request is same origin AND check a CSRF token
- ensure that resources you load are as expected by using [subresource integrity](https://www.w3.org/TR/SRI/)
- use HTTP Strict Transport Security [(HSTS)](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet) with e.g. a "Strict-Transport-Security: max-age=8640000; includeSubDomains" HTTP Header to protected against SSL strip attacks. Consider entering your domain into the [HSTS preload list](https://hstspreload.appspot.com/)
- protect against [clickjacking](https://www.owasp.org/index.php/Clickjacking_Defense_Cheat_Sheet) by using the "X-Frame-Options: DENY" HTTP Header
- Don’t use [JSONP](http://stackoverflow.com/questions/3839966/can-anyone-explain-what-jsonp-is-in-layman-terms) to send sensitive data. Since JSONP is valid JavaScript, it’s not protected by the same-origin policy
- do not eval any non-verified String (e.g. don't eval a String expected to contain JSON - use JSON.parse instead)
- do not store session ids in [LocalStorage](https://www.sitepoint.com/html5-local-storage-revisited/). Think carefully before putting any sensitive data in local storage, even when encrypted
- prefer sessionStorage to localStorage if persistence longer than the browser session is not required
- validate URLs passed to XMLHttpRequest.open (browsers allow these to be cross-domain)
- only use [WebSockets](http://www.html5rocks.com/en/tutorials/websockets/basics/) over TLS (wss://) and be aware that communication can be spoofed / hijacked through XSS
- use [different subdomains](https://www.gov.uk/service-manual/operations/operating-servicegovuk-subdomains.html) for public facing web pages, static assets and administration

## Cookies

- use [secure](https://www.owasp.org/index.php/SecureFlag), signed, [httpOnly](https://www.owasp.org/index.php/HttpOnly) cookies when possible (and mandatory if it contains account information)
- encrypt any sensitive data with e.g. [cookie-encyption (node)](https://www.npmjs.com/package/cookie-encryption)
- avoid putting sensitive information in 3rd party cookies

## Testing

- favour [Test Driven Development](https://en.wikipedia.org/wiki/Test-driven_development) to encourage good test coverage and application design
- test in an environment configured like live (infrastructure, replication, TLS etc.) with similar data profiles (but not with live data) as early as possible
- any testing against live data in non prod environments (even if scrubbed / anonymised) needs appropriate signoff
- use Continuous Integration (CI) and ensure good automated unit, integration, acceptance, smoke, performance, security tests
- undertake an IT Health Check (ITHC, [Penetration Test, Pen Test](https://en.wikipedia.org/wiki/Penetration_test)) for new services or significant changes
- consider use of a version of [chaos monkey](http://www.ibm.com/developerworks/library/a-devops4/) e.g. [Simian Army](https://github.com/Netflix/SimianArmy) to test random instance failures

## Running application

- always use HTTPS (ensure you use [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security) 1.2)
- web applications must use a properly configured Web Application Firewall [(WAF)](https://www.owasp.org/index.php/Web_Application_Firewall) e.g. [NAXSI](https://github.com/nbs-system/naxsi)
- remove unnecessary functionality and code
- if exceptions occur, fail securely
- monitor metrics e.g. [Sysdig](http://www.sysdig.org/)
- create audit for successful and unsuccessful login attempts, unsuccessful authorisation attempts, logouts etc.
- disable unused [HTTP methods](https://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html)
- restrict all applications and services to running with the minimum set of privileges / permissions
- isolate dev environments from the production network, and allow access to dev from authorised users only (dev environments can be a common attack vector)

## Validation

- perform integrity checks to ensure there has been no tampering of e.g. hidden fields or transaction ids. Can use [checksum](https://en.wikipedia.org/wiki/Checksum), [HMAC](https://tools.ietf.org/html/rfc2104), encryption or digital signature depending on the risk
- server-side validation of all inputs, including headers, cookies, redirects
- prefer to [accept known good](https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet) input rather than [reject known bad](https://www.owasp.org/index.php/Data_Validation#Reject_known_bad) input
- sanitise input if necessary (e.g. strip out whitespace or hyphens from phone numbers)
- ensure option selects, checkbox and radio contain only allowable (given) values
- validate data type / length / range / allowed chars
- always re-validate previously entered form data in case it has been surreptitiously altered; hidden fields should be validated too
- all validation failures should result in input rejection with an appropriate message to the user
- have automated tests to check a reasonable range of validation failures are as expected


## Error handling and logging

- do not log sensitive information (e.g. account information or session identifiers) unless necessary
- ensure no debugging / stack traces are displayed to the end user in production
- use generic error messages and custom error pages in production
- prevent tampering of logs by ensuring they are read only and do not allow deletions
- ensure a mechanism exists to conduct log analysis
- restrict access to logs

## Data protection

- do not store passwords, connection strings etc. in plain text
- understand the data that will be used, its retention and removal policy
- understand who will be accessing the service / data, with what devices via what networks / 3rd party services
- only store and use the minimum amount of data required to fulfil the user need; allow users to view only the data they need
- don't (provide interfaces that) allow arbitrary querying of data
- don't allow download of bulk data-sets or too much data to be visible on a page
- rate limit access to large data-sets and record access attempts (also limit the number of transactions a user or device can perform in a given time period)
- enforce use of database schemas, even for noSQL databases by using e.g. [Mongoose](http://mongoosejs.com/docs/guide.html) for MongoDB
- avoid caching data within services unless necessary
- protect caches / temp files containing sensitive data from unauthorised usage and purge them ASAP
- use synchronous cryptography (shared secret) e.g. [AES](https://en.wikipedia.org/wiki/Advanced_Encryption_Standard) to encrypt / decrypt your own data if its sensitive.
- Ensure a shared key is held securely and separately to the data, preferably in a separate key vault (e.g. [Vault](https://www.vaultproject.io/)) that your service can access when it needs a key
- use a key management process e.g. leveraging [Amazon KMS](https://aws.amazon.com/kms/)
- encrypt backups (you will need to know which keys are required to handle which version)
- encode fields that have especially sensitive values
- disable autocomplete on forms for sensitive fields
- not transmit any sensitive information within the URL
- disable client-side caching for pages containing sensitive data by using appropriate [HTTP cache headers](https://www.keycdn.com/blog/http-cache-headers/) i.e. "Cache-Control: no-store", "Expires: 0" and "Pragma: no-cache"
- anonymise data (ensuring re-identification cannot take place) sent to reporting tools or being used as test data
- consider encrypting partially completed forms under a key held by the user if you do not need to use this data
- applications should connect to databases with different credentials for each trust distinction e.g. user, read-only, admin, guest

## Authentication / authorisation

- refer to the [CESG password guidance](https://www.cesg.gov.uk/guidance/password-guidance-simplifying-your-approach) when deciding your password policy for users
- if authentication is required, authenticate and authorise on every request
- use centralised authentication controls, favour SSO
- if authentication services go down they should not give users unauthorised access
- authentication failure should give no information as to which part failed - all error responses should be generic and the same
- separate authentication and authorisation from the resource that is being requested
- admin / account management functions should be particularly secure
- any credential store should only use cryptographically strong one-way salted hashes that don’t allow brute-force attacks. (use bcrypt, scrypt or PBKDF2). Salt length should be at least 128 bits and can be stored in db (prevents [rainbow attacks](http://security.stackexchange.com/questions/379/what-are-rainbow-tables-and-how-are-they-used))
- enforce the changing of temporary or default passwords when they are used
- password reset links should be time-limited and one-time use only
- prevent users from reusing a password
- notify users when a password reset occurs
- indicate the last attempted login to a user
- think carefully about the implications of using "Remember Me"
- re-authenticate users before performing any critical operation such as uploading files
- more secure: use multi-factor authentication (MFA / 2FA) to obtain one-time passwords (OTP). Favour [Google Authenticator](https://en.wikipedia.org/wiki/Google_Authenticator), [Authy](https://www.authy.com/developers/) etc. over SMS (which has weak encryption standards that allow for man-in-the-middle attacks)
- consider introducing captcha after a number of login failures
- lock the account after a number of login failures for a given period of time
- enable all users to be force logged out (e.g. invalidating all session cookies)
- be prepared to change the hashing mechanism; ensure you can do it in the fly when users need to log in

## Session management

- session IDs should be unique, non guessable and non-sequential and suitably long
- use [httpOnly](https://www.owasp.org/index.php/HttpOnly), [secure](https://www.owasp.org/index.php/SecureFlag), [session cookies](http://cookiecontroller.com/internet-cookies/session-cookies/) to store session ids client-side
- use httpOnly, secure, signed, encrypted session cookies if you want to store session data client-side
- set the path and domain for cookies to a suitably restricted value
- session inactivity timeout should be as short as possible
- logout should always be available
- expire session ids after a defined period (to reduce impact of session hijacking)
- session invalidation (due to e.g. timeout, logout, expiration or unauthorised reuse) should immediately delete the session id + session data on the server and client (include a Set-Cookie directive in the response with an expiration time in the past)
- always create a new session when re-authenticating, to avoid [session fixation](https://www.owasp.org/index.php/Session_fixation) attacks
- sensitive session data should be stored on the server
- clear out expired server-side session data frequently
- do not allow concurrent logins for the same user id
- session identifiers should only be in the HTTP cookie header (not in a GET request or anywhere else)
- for sensitive data require per request rather than per session tokens

## Integration

- ensure there is a clear, tightly defined schema using e.g. [JSON Schema](http://json-schema.org/) for each integration point and ensure all input is validated against this schema
- automated tests should verify that messages conform to the expect schema for each integration point
- rate limit inputs and check payload size
-- consider using the [circuit breaker](http://martinfowler.com/bliki/CircuitBreaker.html) design pattern at integration points

## Communication security

- implement transport encryption for the transmission of all sensitive information and supplement with encryption of the payload if necessary
- ensure TLS certificates cover the domain and sub-domains, are current and from a trusted Certificate Authority, and be installed with intermediate certificates when required
- specify character encodings for all connections
- do not allow the mix of TLS and non-TLS content
- filter parameters containing sensitive info in the HTTP referer header when linking to external sites



## File uploads

- require authentication first if appropriate
- check file type, characters, size etc.
- virus / malware scan, preferably in a disposable container
- turn of exec privileges on file upload directories and ensure file is read-only

## Web service security
- OWASP have a good [REST Security Cheatsheet](https://www.owasp.org/index.php/REST_Security_Cheat_Sheet)
- favour JSON Web Tokens [(JWT)](https://jwt.io/) in the header as the format for security tokens and protect their integrity with a [MAC](https://en.wikipedia.org/wiki/Message_authentication_code)
- use API Keys in the authorization header to throttle clients and reduce impact of denial of service attacks. Do not rely on them to protect sensitive resources because they are easy to compromise
- consider 2-way TLS [client certs](https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet#Client-Side_Certificates) if your application is integrating via a web service. However, implementation and trouble-shooting can be onerous and revoking and reissuing certificates a complexity
- whitelist allowable methods and reject non-allowed with 405
- be aware of authorisation needs in service-to-service communication, and avoid the confused deputy problem where a service calls another without providing the appropriate authorisation information. Using [external ids](https://aws.amazon.com/blogs/security/how-to-use-external-id-when-granting-access-to-your-aws-resources/) can help here. 
- the server should always send the Content-Type header with the correct Content-Type, and include a charset
- reject a request with 406 Not Acceptable response if the Content-Type is not supported
- disable CORS headers unless cross-domain calls are needed. If they are needed, be as specific as possible
- consider logging token validation errors to help detect attacks


# Automated security testing
Whilst projects will have a penetration test and IT health check, these are periodic tasks. We also encourage teams to run automated security testing tools so they can pick up security vulnerabilities much more quickly. We recommend that security testing tools are run on a regular basis, not just when code is pushed. This is because new vulnerabilities may emerge without you having made any changes to your application.

## NodeJS dependency security testing - Snyk
Snyk checks your NodeJS applications dependencies for vulnerabilities.

We recommend 2 ways to use Snyk:

1) Github integration
Snyk can automatically raise PRs against your repository to fix vulnerabilities, more details available here:  
https://snyk.io/docs/github/

2) Manually
Snyk has a CLI that you can use manually or as part of a CI pipeline. The easiest way to configure this is to:
  - Locally run **snyk wizard**
  - The wizard will offer to add code to your package json to run snyk vulnerability testing alongside your usual npm test jobs
  - Accept this and any CI test jobs will fail if there are new vulnerabilities

## Scala dependency security testing -  SBT Dependency Check
SBT Dependency Check checks your dependencies against the OWASP database of vulnerable modules. It does work but is relatively immature, so not as easy to use as Snyk. [You can find SBT dependency check here](https://github.com/albuch/sbt-dependency-check)

## Java dependency security testing
OWASP provide some tools for this, which includes a command line tool as well as a maven plugin. This is essentially the same tool as SBT Dependency Check above, just more for Java. [You can find Dependency Check for Java here](https://www.owasp.org/index.php/OWASP_Dependency_Check)

## Tech specific libraries

- Node
    - [Lusca](https://github.com/krakenjs/lusca)
    - [helmet](https://github.com/helmetjs/helmet)
    - [node security project](https://nodesecurity.io/) [nsp on GitHub](https://github.com/nodesecurity/nsp)

## Useful resources and books

- [National Cyber Security Centre Secure Development Practices Guide](https://github.com/ukncsc/secure-development-and-deployment/)
- [OWASP Top 10 Project](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project)
- [Web Application Security - A Beginner's Guide](https://www.mhprofessional.com/product.php?isbn=0071776168)
- [Identity and Data Security for Web Developers](http://shop.oreilly.com/product/0636920044376.do)
- [The Web Application Hacker's Handbook](http://eu.wiley.com/WileyCDA/WileyTitle/productCd-1118026470.html)
- [HTTP protocol security considerations](https://www.w3.org/Protocols/rfc2616/rfc2616-sec15.html)
- [OWASP cheat sheets](https://www.owasp.org/images/9/9a/OWASP_Cheatsheets_Book.pdf)
- [OWASP secure coding practices](https://www.owasp.org/images/0/08/OWASP_SCP_Quick_Reference_Guide_v2.pdf)
- [CESG Enterprise security decisions](https://www.cesg.gov.uk/guidance/security-considerations-common-enterprise-it-decisions)
- [CESG password guidance](https://www.cesg.gov.uk/guidance/password-guidance-simplifying-your-approach)
- [CESG 10 steps to cyber security](https://www.cesg.gov.uk/10-steps-cyber-security)
- [CESG Protecting bulk and personal data](https://www.cesg.gov.uk/guidance/protecting-bulk-personal-data)
- [CESG Security Design Principles for Digital Services](https://www.cesg.gov.uk/guidance/security-design-principles-digital-services-0)
- [CESG TLS guidance for external services](https://www.cesg.gov.uk/guidance/transport-layer-security-tls-external-facing-services)
