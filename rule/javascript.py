from rule import Rule
import re

JavascriptRules = [
    Rule(
        'The eval function is extremely dangerous, because if any user input that is not treated is passed to it, it may be possible to execute code remotely in the context of your application (RCE - Remote Code Executuion)',
        '',
        'Injection',
        ExactMatch = re.compile(r'(eval\(.*)(?:req\.|req\.query|req\.body|req\.param)')
    ),

    Rule(
        'Passing untreated parameters to queries in the database can cause an SQL injection, or even a NoSQL query injection.',
        '',
        'Injection',
        ExactMatch = re.compile(r'\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:\'|\'|\):.*(?:req\.|req\.query|req\.body|req\.param)')
    ),

	Rule(
        'The setTimeout function is very dangerous because it can interpret a string as code.',
        '',
        'Injection',
        ExactMatch = re.compile(r'(setTimeout\(.+)(req\.|req\.query|req\.body|req\.param)')
    ),

    Rule(
        'The setInterval function is very dangerous because it can interpret a string as code..',
        '',
        'Injection',
        ExactMatch = re.compile(r'(setInterval\(.+)(req\.|req\.query|req\.body|req\.param)')
    ),

	Rule(
        'If a user-controlled data that has not been processed reaches the \'load\' function, it is possible for an attacker to execute code within your application. Reference at: https://www.npmjs.com/advisories/813',
        '',
        'Injection',
        ExactMatch = re.compile(r'(require\(\'js-yaml\'\)\.load\(|yaml\.load\()')
    ),

    Rule(
        'The NODE_TLS_REJECT_UNAUTHORIZED option being disabled allows the Node.js server to accept certificates that are self-signed, allowing an attacker to bypass the TLS security layer.',
        '',
        'Security Misconfiguration',
		ExactMatch =  re.compile(r'(?:\[|)(?:\'|")NODE_TLS_REJECT_UNAUTHORIZED(?:\'|")')
    ),

	Rule(
        'The SSL_VERIFYPEER option controls the internal Node.js library, causing HTTPS requests to stop checking if a secure cryptographic tunnel has actually been established between the servers, allowing an attacker to intercept client communication in open text.',
        '',
        'Security Misconfiguration',
        ExactMatch = re.compile('SSL_VERIFYPEER\s*:\s*0')
        ),

	Rule(
        'A hash algorithm used is considered weak and can cause hash collisions.',
        'It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.',
        'Security Misconfiguration',
		ExactMatch = re.compile('createHash\((?:'|')md5(?:'|')')
    ),

	Rule(
        'A hash algorithm used is considered weak and can cause hash collisions.',
        'It is always recommended to use some CHF (Cryptographic Hash Function), which is mathematically strong and not reversible. SHA512 would be the most recommended hash for storing the password and it is also important to adopt some type of Salt, so that the Hash is more secure.',
        'Security Misconfiguration',
		ExactMatch = re.compile('createHash\((?:'|')sha1(?:'|')')
    ),

	Rule(
        'Using the Handlebars SafeString function is dangerous as the data passed to it does not undergo any internal validation, so a malicious input can cause an XSS',
        '',
        'Injection',
		ExactMatch = re.compile('handlebars\.SafeString\(')
    ),

	Rule(
        'User data passed untreated to the \'createReadStream\' function can cause a Directory Traversal attack.',
        '',
        'Broken Access Control',
		ExactMatch = re.compile('\.createReadStream\(.*(?:req\.|req\.query|req\.body|req\.param)')
    ),

	Rule(
        'User data passed untreated to the \'createReadStream\' function can cause a Directory Traversal attack.',
        '',
        'Broken Access Control',
		ExactMatch = re.compile('\.readFile\(.*(?:req\.|req\.query|req\.body|req\.param)')
    ),

	Rule(
        'When passing user data directly to the HTTP response headers, it is possible for an XSS to become viable.',
        '',
        'Cross-Site Scripting',
		ExactMatch = re.compile('res\.(write|send)\(.*(?:req\.|req\.query|req\.body|req\.param)')
    ),

	Rule(
        'The HTTP header X-XSS-Protection activates protection on the user\'s browser side to mitigate XSS-based attacks. It is important to keep it activated whenever possible.',
        '',
        'Cross-Site Scripting',
		ExactMatch = re.compile('(?:\[|)(?:'|')X-XSS-Protection(?:'|')(?:\]|)\s*=\s*(?:'|')*0(?:'|')')
    ),

	Rule(
        'Using the \'redirect\' function can cause an Open Redirect.',
        '',
        'Broken Access Control',
		ExactMatch = re.compile('res\.redirect\(')
    ),

	Rule(
        'Allowing data from user input to be used as parameters for the unhandled \'request\' method could cause a Server Side Request Forgery vulnerability',
        '',
        'Cross-Site Scripting',
        And = [re.compile(r'require\((?:\'|")request(?:\'|\")\)'), re.compile(r'request\(.*(req\.|req\.query|req\.body|req\.param)')]
    ),

	Rule(
        'Allowing data from user input to be used as parameters for the \'request.get\' method without treatment could cause a Server Side Request Forgery vulnerability',
        '',
        'Cross-Site Scripting',
        And = [re.compile(r'require\((?:\'|")request(?:\'|")\)'), re.compile(r'\.get\(.*(req\.|req\.query|req\.body|req\.param)')]
    ),

	Rule(
        'Allowing data from user input to be used as parameters for the \'needle.get\' method without treatment could cause a Server Side Request Forgery vulnerability',
        'Cross-Site Scripting',
        '',
        And = [re.compile(r'require\((?:\'|")needle(?:\'|")\)'), re.compile(r'\.get\(.*(req\.|req\.query|req\.body|req\.param)')]
    ),

	Rule(
        'Allowing data from user input to reach the \'exec\' command without treatment could cause a Remote Code Execution vulnerability',
        'Cross-Site Scripting',
        '',
        And = [re.compile(r'require\((?:\'|")child_process(?:\'|")\)'), re.compile(r'\.exec\(.*(req\.|req\.query|req\.body|req\.param)')]
    )
]
