from rule import Rule
import re

CsharpRules = [  
    # Rule(
    #     'The dynamic value passed for the execution of the command must be validated. https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo?view=netframework-4.8',
    #     '',
    #     'Injection',
    #     Or = [re.compile(r'ExecuteDataSet'), re.compile(r'ExecuteQuery')]
    #     # Or = [re.compile(r'ExecuteDataSet'), re.compile(r'.*\.ExecuteQuery\(@".*\+')]
    #     # ExactMatch = re.compile(r'.*\.ExecuteQuery\(@".*')
    # ),

    Rule(
        'The dynamic value passed for the execution of the command must be validated. https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.processstartinfo?view=netframework-4.8',
        '',
        'A1: Injection',
        Severity = "INFO",
        CWE  = "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        ExactMatch = re.compile(r'.*=\s+new\sProcess\(\);(?:.*)*(.*\.StartInfo\.Arguments\s+=\s+.*".*\+)')
    ),

    Rule(
        'The application appears to write confidential information to log files, creating a risk of theft of credentials and / or private information. https://cwe.mitre.org/data/definitions/532.html',
        '',
        'A1: Injection',
        Severity = "WARNING",
        CWE  = "CWE-532: Insertion of Sensitive Information into Log File",
        ExactMatch = re.compile(r'(?:\bLogError|\bLogger|\blogger|\bLogging|\blogging|System\.Diagnostics\.Debug|System\.Diagnostics\.Trace).*\(.*\+\s*(?:pass|pwd|passwd|password|key|cert|privKey|privateKey)')
    ),

	Rule(
        'Validation of user entries has been disabled. The ASP.NET request validation feature proactively prevents code injection attacks by not allowing unencrypted HTML content to be processed by the server, unless the developer decides to allow that content. When request validation is disabled, content can be sent to a page; it is the responsibility of the page developer to ensure that the content is encoded or processed correctly. https://docs.microsoft.com/en-us/aspnet/whitepapers/request-validation.',
        '',
        'A6: Security Misconfiguration',
        Severity = "ERROR",
        CWE  = "CWE-554: ASP.NET Misconfiguration: Not Using Input Validation Framework",
        ExactMatch = re.compile(r'<pages(?:>|)\s+.*validateRequest=[\'"]+false')
    ),

    Rule(
        'The application uses the potentially dangerous Html.Raw construct in conjunction with a user-supplied variable. The recommendation is to avoid using HTML assembly, but if it is extremely necessary to allow Html, we suggest the following: support only a fixed subset of Html, after the user submits content, analyze the Html and filter it in a whitelist of allowed tags and attributes. Be very careful when filtering and eliminating anything you are unsure of. https://owasp.org/www-community/attacks/xss/.',
        '',
        'A7: XSS',
        Severity = "WARNING",
        CWE  = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        ExactMatch = re.compile(r'\bHtml\b\.Raw\(')
    ),

	Rule(
        'The application appears to allow XSS through an unencrypted / unauthorized input variable. https://owasp.org/www-community/attacks/xss/.',
        '',
        'A7: XSS',
        Severity = "ERROR",
        CWE  = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        Or = [re.compile(r'\s+var\s+\w+\s*=\s*"\s*\<\%\s*=\s*\w+\%\>";'), re.compile(r'\.innerHTML\s*=\s*.+')]
    ),

    Rule(
        'The code uses standard strings and byte arrays to store sensitive transient data, such as passwords and private encryption keys, instead of the SecureString class which is more secure because it encrypts the data at rest https://docs.microsoft. com / en-us / dotnet / api / system.security.securestring? view = netframework-4.8.',
        '',
        'A3: Sensitive Data Exposure',
        Severity = "WARNING",
        CWE  = "CWE-316: Cleartext Storage of Sensitive Information in Memory",
        ExactMatch = re.compile(r'(?mi)\b(?:string|char\[)\s+(?:pass|pwd|passwd|password|key|cert|privKey|privateKey).*')
    ),

    Rule(
        'The code performs entire operations with a deliberate deactivation of defenses against overflow. As overflowing verification takes time, using unverified code in situations where there is no danger of overflow can improve performance. However, if overflow is a possibility, protection must be enabled or actively monitor the environment. https://docs.microsoft.com/en-us/dotnet/csharp/language-reference/keywords/unchecked.',
        '',
        'A9: Using Components with Known Vulnerabilities',
        Severity = "WARNING",
        CWE  = "CWE-129: Improper Validation of Array Index",
        ExactMatch = re.compile(r'\bint\b\s*\w+\s*\=\s*\bunchecked\b\s+\(')
    ),
    
    Rule(
        'The application appears to execute commands on the underlying system, check that no user-controlled variables are used without proper sanitation in this command. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca3006?view=vs-2019.',
        '',
        'A1: Injection',
        Severity = "ERROR",
        CWE  = "CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
        ExactMatch = re.compile(r'\.ProcessStartInfo\(')
    ),

    Rule(
        'The code allows objects to be deserialized. This can allow potentially hostile objects to be instantiated directly from the data held in the file system. Insecure deserializers are vulnerable when deserializing untrusted data. An attacker could modify the serialized data to include unexpected types to inject objects with malicious side effects. An attack against an insecure deserializer can, for example, execute commands on the underlying operating system, communicate over the network, or delete files. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca2300?view=vs-2019.',
        '',
        'A8: Insecure Deserialization',
        Severity = "WARNING",
        CWE  = "CWE-502: Deserialization of Untrusted Data",
        ExactMatch = re.compile(r'\.(?:Deserialize|ReadObject)\(')
    ),

    Rule(
        'The code appears to use the Next () and / or NextBytes () functions. The resulting values, while seeming random to a casual observer, are predictable and can be enumerated by a skilled and determined attacker, although this is partially mitigated by a non-time-based seed. To generate a cryptographically secure random number suitable for creating a random password, use a method like RNGCryptoServiceProvider.GetBytes. https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider.getbytes?view=netframework-4.8',
        '',
        'A5: Broken Access Control',
        Severity = "INFO",
        CWE  = "CWE-330: Use of Insufficiently Random Values",
        ExactMatch = re.compile(r'\bRandom\.(?:Next\(|NextBytes\()')
    ),
    
    Rule(
        'The application appears to create a temporary file with a static, encoded name. This can cause security problems in the form of a classic race condition (an attacker creates a file with the same name between creating the application and attempting to use it) or a symbolic link attack in which an attacker creates a symbolic link at the location of the temporary file. We recommend using the Path.GetTempFileName method. https://owasp.org/www-community/vulnerabilities/Insecure_Temporary_File',
        '',
        'A9: Using Components with Known Vulnerabilities',
        Severity = "WARNING",
        CWE  = "CWE-377: Insecure Temporary File",
        ExactMatch = re.compile(r'=\s+File\.Open\(".*(?:\.|)(?:temp|tmp|temporary).*"(?:,|)')
    ),
    
    Rule(
        'The application is configured to display standard .NET errors. This can provide the attacker with useful information and should not be used in a production application. https://docs.microsoft.com/en-us/aspnet/web-forms/overview/older-versions-getting-started/deploying-web-site-projects/displaying-a-custom-error-page-cs',
        '',
        'A6: Security Misconfiguration',
        Severity = "INFO",
        CWE  = "CWE-12: ASP.NET Misconfiguration: Missing Custom Error Page",
        ExactMatch = re.compile(r'<\s*customErrors\s+mode\s*=\s*"Off"\s*/>')
    ),
    
    Rule(
        'ASP.NET allows remote debugging of Web applications, if configured to do so. By default, debugging is subject to access control and requires platform-level authentication. If an attacker can successfully initiate a remote debugging session, it is likely that it will disclose sensitive information about the web application and the supporting infrastructure that can be valuable in formulating targeted system attacks. To disable debugging, open the Web.config file for the application and find the <compilation> element in the <system.web> section. Set the debug attribute to \'false\'. Note that it is also possible to enable debugging for all applications in the Machine.config file. You must confirm that the debug attribute in the <compilation> element has not been set to \'true\' in the Machine.config file. https://support.microsoft.com/en-us/help/815157/how-to-disable-debugging-for-asp-net-applications',
        '',
        'A6: Security Misconfiguration',
        Severity = "INFO",
        CWE  = "CWE-11: ASP.NET Misconfiguration: Creating Debug Binary",
        ExactMatch = re.compile(r'\bdebug\s*=\s*"\s*true\s*"')
    ),
    
    Rule(
        'The potentially unsafe HTTP request entry reaches an XPath query. The dynamic value passed to the XPath query must be validated. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca3008?view=vs-2019',
        '',
        'A1: Injection',
        Severity = "INFO",
        CWE  = "CWE-643: Improper Neutralization of Data within XPath Expressions ('XPath Injection')",
        ExactMatch = re.compile(r'.*=\s+new\sXmlDocument\s*(?:\(\)|{.*});(?:.*)*(.*\.SelectNodes\(\s*.*".*\+)')
    ),

    Rule(
        'If you use unsafe DtdProcessing instances or refer to sources from external entities, the analyzer can accept untrusted input and disclose confidential information to attackers. The operation may be vulnerable to processing XML eXternal Entity (XXE) .https: //docs.microsoft.com/en-us/visualstudio/code-quality/ca3075? View = vs-2019',
        '',
        'A4: XML External Entities (XXE)',
        Severity = "WARNING",
        CWE  = "CWE-611: Improper Restriction of XML External Entity Reference",
        ExactMatch = re.compile(r'.*=\s+new\sXmlReaderSettings\s*(?:\(\)|{.*});(?:.*)*(.*\s+=\s+DtdProcessing\.Parse;)')
    ),
    
    Rule(
        'A path traversal attack (also known as directory traversal) has been detected. This attack aims to access files and directories stored outside the expected directory. The most effective way to avoid cross-file file path vulnerabilities is to avoid passing user-provided input to the file system APIs. Many application functions that do this can be rewritten to provide the same behavior more securely. https://portswigger.net/web-security/file-path-traversal',
        '',
        'A5: Broken Access Control',
        Severity = "WARNING",
        CWE  = "CWE-23: Relative Path Traversal",
        And = [re.compile(r'using\sSystem\.Web\.Mvc;'), re.compile(r'using\sSystem\.Web;'), re.compile(r'.*\s+:\s+Controller'), re.compile(r'.*Server\.MapPath\(".*\+')]
    ),
    
    Rule(
        'A potential Cross-Site Scripting (XSS) was found. The endpoint returns a variable from the client entry that has not been coded. Always encode untrusted input before output, regardless of validation or cleaning performed. https://docs.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-3.1',
        '',
        'A7: XSS',
        Severity = "ERROR",
        CWE  = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        ExactMatch = re.compile(r'(?:public\sclass\s.*Controller|.*\s+:\s+Controller)(?:.*)*return\s+.*".*\+')
    ),
    
    Rule(
        'The potentially unsafe HTTP request entry reaches an LDAP instruction. The dynamic value passed to the LDAP query must be validated. For the user-controlled portion of LDAP instructions, consider one of the following: Allow only a safe list of non-special characters; Do not allow special characters; Escape from special characters. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca3005?view=vs-2019',
        '',
        'A1: Injection',
        Severity = "ERROR",
        CWE  = "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')",
        ExactMatch = re.compile(r'.*=\s+new\sDirectorySearcher\s*(?:\(\)|{.*});(?:.*)*(.*\.Filter\s+=\s+".*\+)')
    ),
    
    Rule(
        'A weak password can be guessed or forced. PasswordValidator must have at least four or five requirements to improve security (RequiredLength, RequireDigit, RequireLowercase, RequireUppercase and / or RequireNonLetterOrDigit).',
        '',
        'A2: Broken Authentication',
        Severity = "INFO",
        CWE  = "CWE-521: Weak Password Requirements",
        ExactMatch = re.compile(r'new\s+PasswordValidator(?:.*)*{')
    ),
    
    Rule(
        'A possible SQL Injection vulnerability was found. SQL injection failures are introduced when software developers create dynamic database queries that include user-supplied input. Always validate user input by testing type, length, shape and reach. When implementing precautions against malicious entry, consider your application\'s architecture and deployment scenarios. Remember that programs designed to run in a secure environment can eventually be copied to an unsafe environment.https: //docs.microsoft.com/en-us/sql/relational-databases/security/sql-injection? view = sql-server-ver15',
        '',
        'A1: Injection',
        Severity = "ERROR",
        CWE  = "CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')",
        Or = [re.compile(r'.*\s+new\sOdbcCommand\(.*".*\+(?:.*)*.ExecuteReader\('), re.compile(r'.*\s+new\sSqlCommand\(.*".*\+'), re.compile(r'.*\.ExecuteDataSet\(.*".*\+'), re.compile(r'ExecuteQuery\(@".*')]
    ),
    
    Rule(
        'The pseudo-random numbers generated are predictable. When the software generates predictable values in a context that requires unpredictability, it may be possible for an attacker to guess the next value that will be generated and use that guess to impersonate another user or access confidential information. To generate a cryptographically secure random number, such as the one suitable for creating a random password, use the RNGCryptoServiceProvider class or derive a class from System.Security.Cryptography.RandomNumberGenerator.https: //docs.microsoft.com/en-us/dotnet/ api / system.random? view = netframework-4.8',
        '',
        'A5: Broken Access Control',
        Severity = "INFO",
        CWE  = "CWE-330: Use of Insufficiently Random Values",
        ExactMatch = re.compile(r'=\s+new\s+Random\(\);')
    ),
    
    Rule(
        'MD5 or SHA1 can cause collisions and are considered weak hashing algorithms. A weak encryption scheme may be subject to brute force attacks that have a reasonable chance of success using current methods and resources of attack. Use an encryption scheme that is currently considered strong by experts in the field. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5350?view=vs-2019 https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5351?view = vs-2019',
        '',
        'A6: Security Misconfiguration',
        Severity = "INFO",
        CWE  = "CWE-326: Inadequate Encryption Strength",
        Or = [re.compile(r'=\s+new\s+SHA1CryptoServiceProvider\('), re.compile(r'=\s+new\s+MD5CryptoServiceProvider\(')]
    ),
    
    Rule(
        'DES / 3DES is considered a weak cipher for modern applications. A weak encryption scheme may be subject to brute force attacks that have a reasonable chance of success using current methods and resources of attack. Use an encryption scheme that is currently considered strong by experts in the field. Currently, NIST recommends using AES block ciphers. http://www.nist.gov/itl/fips/060205_des.cfm https://www.nist.gov/publications/advanced-encryption-standard-aes https://docs.microsoft.com/en-us/ visualstudio / code-quality / ca5351? view = vs-2019.',
        '',
        'A6: Security Misconfiguration',
        Severity = "WARNING",
        CWE  = "CWE-326: Inadequate Encryption Strength",
        Or = [re.compile(r'=\s+new\s+TripleDESCryptoServiceProvider\('), re.compile(r'=\s+new\s+DESCryptoServiceProvider\('), re.compile(r'=\s+TripleDES\.Create\('), re.compile(r'=\s+DES\.Create\(')]
    ),

    Rule(
        'Microsoft believes it is no longer safe to decrypt data encrypted with CBC (Cipher-Block-Chaining) symmetric encryption mode when verifiable padding was applied without first ensuring the integrity of the ciphertext, except in very specific circumstances. This judgment is based on currently known cryptographic research. The CBC mode is susceptible to attack from the padding oracle. The use of AES in CBC mode with an HMAC suffix is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode',
        '',
        'A2: Broken Authentication',
        Severity = "WARNING",
        CWE  = "CWE-310: Cryptographic Issues",
        ExactMatch = re.compile(r'=\s+CipherMode\.CBC')
    ),

    Rule(
        'This mode is not recommended because it opens the door to various security exploits. If the plain text to be encrypted contains substantial repetitions, it is possible that the cipher text will be broken one block at a time. You can also use block analysis to determine the encryption key. In addition, an active opponent can replace and exchange individual blocks without detection, which allows the blocks to be saved and inserted into the stream at other points without detection. ECB mode will produce the same result for identical blocks. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019',
        '',
        'A2: Broken Authentication',
        Severity = "WARNING",
        CWE  = "CWE-310: Cryptographic Issues",
        ExactMatch = re.compile(r'=\s+CipherMode\.ECB')
    ),
    
    Rule(
        'OFB mode will produce the same result for identical blocks, this mode is vulnerable to attack and can cause exposure of confidential information. An attacker could guess the encrypted message. The use of AES in CBC mode with an HMAC is recommended, ensuring integrity and confidentiality. https://docs.microsoft.com/en-us/visualstudio/code-quality/ca5358?view=vs-2019&viewFallbackFrom=vs-2019',
        '',
        'A2: Broken Authentication',
        Severity = "WARNING",
        CWE  = "CWE-310: Cryptographic Issues",
        ExactMatch = re.compile(r'=\s+CipherMode\.OFB')
    ),
    
    Rule(
        'Secure Flag is a policy for the browser to ensure that the cookie is sent over an encrypted channel, using the SSL protocol, that is, only via HTTPS. To set the transmission of cookies using SSL for an entire application, enable it in the application\'s configuration file, Web.config, which resides in the application\'s root directory. https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.secure?view=netframework-4.8',
        '',
        'A3: Sensitive Data Exposure',
        Severity = "INFO",
        CWE  = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
        ExactMatch = re.compile(r'new\sHttpCookie\(.*\)')
    ),
    
    Rule(
        'Cookies that do not have the HttpOnly flag set are available for JavaScript running on the same domain. The assigned value must be \'true\' to enable the HttpOnly attribute and cannot be accessed through a client-side script; otherwise, \'false\'. The default is \'false\'. When a user is the target of an XSS attack, the attacker would benefit from obtaining confidential information or even progressing to a session hijack. https://docs.microsoft.com/en-us/dotnet/api/system.web.httpcookie.httponly?view=netframework-4.8',
        '',
        'A7: XSS',
        Severity = "INFO",
        CWE  = "CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
        ExactMatch = re.compile(r'(?:.*\s+new\sHttpCookie(?:.*)*.HttpOnly\s*=\s*false|httpOnlyCookies\s*=\s*"false")')
    ),
    
    Rule(
        'Web Forms controls use hidden base64-encoded fields to store state information. If confidential information is stored, it can leak to the client side. https://docs.microsoft.com/en-us/dotnet/api/system.web.ui.viewstateencryptionmode?view=netframework-4.8',
        '',
        'A6: Security Misconfiguration',
        Severity = "INFO",
        CWE  = "CWE-311: Missing Encryption of Sensitive Data",
        ExactMatch = re.compile(r'viewStateEncryptionMode\s*=\s*"(?:Auto|Never)"')
    ),
    
    Rule(
        'Request validation is disabled. Request validation allows filtering of some XSS standards sent to the application. https://docs.microsoft.com/en-us/dotnet/api/system.web.mvc.validateinputattribute?view=aspnet-mvc-5.2',
        '',
        'A1: Injection',
        Severity = "INFO",
        CWE  = "CWE-20: Improper Input Validation",
        ExactMatch = re.compile(r'(?:public\s+class\s+.*Controller|.*\s+:\s+Controller)(?:.*)*\[ValidateInput\(false\)\]')
    ),
    
    Rule(
        'The validateRequest flag that provides additional protection against XSS is disabled, \'false\', in the configuration file. ASP.NET examines the browser input for dangerous values when validateRequest \'true\'. https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.pagessection.validaterequest?view=netframework-4.8',
        '',
        'A1: Injection',
        Severity = "INFO",
        CWE  = "CWE-20: Improper Input Validation",
        ExactMatch = re.compile(r'validateRequest\s*=\s*"false"')
    ),
    
    Rule(
        'The requestValidationMode that provides additional protection against XSS is enabled only for pages, not for all HTTP requests in the configuration file. The recommended value is \'4.0\'. https://docs.microsoft.com/en-us/dotnet/api/system.web.configuration.httpruntimesection.requestvalidationmode?view=netframework-4.8',
        '',
        'A1: Injection',
        Severity = "INFO",
        CWE = "CWE-20: Improper Input Validation",
        ExactMatch = re.compile(r'requestValidationMode\s*=\s*"(?:4.[1-9]|3.\d+|2.\d+|1.\d+|0.\d+)"')
    ),
    
    Rule(
        'The password setting for this API appears to be encrypted. https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password',
        '',
        'A3: Sensitive Data Exposure',
        Severity = "WARNING",
        CWE  = "CWE-259: Use of Hard-coded Password",
        ExactMatch = re.compile(r'\.setPassword\("(.*?)"\)')
    ),
    
    Rule(
        'The \'RequiredLength\' property is missing. \'RequiredLength\' must be set to a minimum value of 8.',
        '',
        'A2: Broken Authentication',
        Severity = "INFO",
        CWE  = "CWE-521: Weak Password Requirements",
        ExactMatch = re.compile(r'new\s+PasswordValidator\(\)')
    ),
    
    Rule(
        'The \'RequiredLength\' property must be set to a minimum value of 8.',
        '',
        'A2: Broken Authentication',
        Severity = "INFO",
        CWE  = "CWE-521: Weak Password Requirements",
        ExactMatch = re.compile(r'new\s+PasswordValidator(?:.*)*\{(?:.*)*RequiredLength\s+=\s+[1-7]')
    ),
    
    Rule(
        'The application uses Base64 encoding. The application stores confidential information in clear text in a resource that may be accessible to another sphere of control. Even if the information is encoded in a way that is not readable by humans, certain techniques can determine which encoding is being used and decode the information.',
        '',
        'A3: Sensitive Data Exposure',
        Severity = "INFO",
        CWE  = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'Convert\.ToBase64String\(')
    ),
    
    Rule(
        'The application uses the \'not secure\' directive, which allows the use of C-style pointers in the code. This code has a high risk of unexpected behavior, including buffer overflows, memory leaks and failures. https://docs.microsoft.com/en-us/dotnet/csharp/programming-guide/unsafe-code-pointers/',
        '',
        'A9: Using Components with Known Vulnerabilities',
        Severity = "INFO",
        CWE  = "CWE-787: Out-of-bounds Write",
        ExactMatch = re.compile(r'\bunsafe\b')
    ),
    
    Rule(
        'The [OutputCache] annotation will disable the [Authorize] annotation for requests after the first.',
        'Do not store confidential information unnecessarily in the cache. Protect the information stored in the cache.',
        'A3: Sensitive Data Exposure',
        Severity = "INFO",
        CWE  = "CWE-524: Use of Cache Containing Sensitive Information",
        ExactMatch = re.compile(r'(?:public\s+class\s+.*Controller|.*\s+:\s+Controller)(?:.*)*\[OutputCache\]')
    ),
    
    Rule(
        'The Anti-forgery token is missing. Without this validation, an attacker could send a link to the victim and, visiting the malicious link, a web page would trigger a POST request (because it is a blind attack - the attacker does not see a response to the triggered request and does not have the use of the GET request and GET requests must not change a server state by default) for the site. The victim would not be able to recognize that an action is taken in the background, but his cookie would be sent automatically if he was authenticated on the website. This attack requires no special interaction other than visiting a website.',
        'To help prevent CSRF attacks, ASP.NET MVC uses anti-forgery tokens, also called request verification tokens.',
        'A7: XSS',
        Severity = "INFO",
        CWE  = "CWE-352: Cross-Site Request Forgery (CSRF)",
        ExactMatch = re.compile(r'(?:public\s+class\s+.*Controller|.*\s+:\s+Controller)(?: .*)*'),
        NotOr = [re.compile(r'\[ValidateAntiForgeryToken\]')]
    )
]