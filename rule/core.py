from rule import Rule
import re

'''
    Covered OWASP 3 (Sensitive Data Exposure), 7 (XSS)
'''

CoreRules = [
    Rule(
		'There are ‘Secrets Management’ solutions that can be used to store secrets.',
        'Credentials must not be stored in the code, an attacker could decompile the application and obtain the credential.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
        ExactMatch = re.compile(r'\d{2,3}\.\d{2,3}\.\d{2,3}\.\d{2,3}')
	),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
	    'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}')
    ),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
        'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(?i)aws(.{0,20})?[\'\"][0-9a-zA-Z\/+]{40}[\'\"]')		 
	),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    ),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(chave\s*=\s*[\'|\"]\w+[\'|\"])|(\w*[tT]oken\s*=\s*[\'|\"]\w+[\'|\"])|(\w*[aA][uU][tT][hH]\w*\s*=\s*[\'|\"]\w+[\'|\"])|(username\s*=\s*[\'|\"]\w+[\'|\"])|(secret\s*=\s*[\'|\"]\w+[\'|\"])|(chave\s*=\s*[\'|\"]\w+[\'|\"])'),
		NotOr = [re.compile(r'(?mi)public.*[tT]oken'), re.compile(r'(?mi)public.*[kK]ey')]
	),

	Rule(
        'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'-----BEGIN PRIVATE KEY-----')
	),

	Rule(
        'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'AAAA(?:[0-9A-Za-z+/])+={0,3}(?:.+@.+)')
	),

	Rule(
        'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----')
	),

	Rule(
        'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----')
	),

	Rule(
        'Facebook Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(facebook|fb)(.{0,20})?[\'\"][0-9a-f]{32}[\'\"]')
	),

	Rule(
        'Facebook Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(facebook|fb)(.{0,20})?[\'\"][0-9]{13,17}[\'\"]')
	),

	Rule(
        'Facebook Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+'),
	),

	Rule(
		'Twitter Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(?i)twitter(.{0,20})?[\'\"][0-9a-z]{35,44}[\'\"]')
	),

	Rule(
		'Twitter Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
        'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)twitter(.{0,20})?[\'\"][0-9a-z]{18,25}[\'\"]')
	),

	Rule(
		'GitHub URL. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)github(.{0,20})?[\'\"][0-9a-zA-Z]{35,40}[\'\"]'),
	),

	Rule(
		'LinkedIn Client ID. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)linkedin(.{0,20})?[\'\"][0-9a-z]{12}[\'\"]')
	),

	Rule(
		'LinkedIn Secret Key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)linkedin(.{0,20})?[\'\"][0-9a-z]{16}[\'\"]')
	),

	Rule(
		'Slack API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'xox[baprs]-([0-9a-zA-Z]{10,48})?')
	),

	Rule(
		'EC key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'-----BEGIN EC PRIVATE KEY-----')
	),

	Rule(
		'Generic API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(?i)api_key(.{0,20})?[\'\"][0-9a-zA-Z]{32,45}[\'\"]')
	),

	Rule(
		'Google API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'AIza[0-9A-Za-z\-_]{35}')
	),

	Rule(
		'Google Cloud Platform API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(google|gcp|youtube|drive|yt)(.{0,20})?[\'\"][AIza[0-9a-z\-_]{35}][\'\"]')
	),

	Rule(
		'Google OAuth. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(google|gcp|auth)(.{0,20})?[\'\"][0-9]+-[0-9a-z_]{32}\.apps\.googleusercontent\.com[\'\"]')
	),

	Rule(
		'Google OAuth Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'ya29\.[0-9A-Za-z\-_]+')
	),

	Rule(
		'Heroku API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)heroku(.{0,20})?[\'\"][0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[\'\"]')
	),

	Rule(
		'MailChimp API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(mailchimp|mc)(.{0,20})?[\'\"][0-9a-f]{32}-us[0-9]{1,2}[\'\"]')
	),

	Rule(
		'Mailgun API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)(mailgun|mg)(.{0,20})?[\'\"][0-9a-z]{32}[\'\"]')
	),

	Rule(
		'Password in URL. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@.{1,100}/?.?')
	),

	Rule(
		'PayPal Braintree Access Token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}')
	),

	Rule(
		'Picatic API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'sk_live_[0-9a-z]{32}')
	),

	Rule(
		'Stripe API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)stripe(.{0,20})?[\'\"][sk|rk]_live_[0-9a-zA-Z]{24}')
	),

	Rule(
		'Square access token. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'sq0atp-[0-9A-Za-z\-_]{22}')
	),

	Rule(
		'Square OAuth secret. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}')
	),

	Rule(
		'Twilio API key. File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'(?i)twilio(.{0,20})?[\'\"][0-9a-f]{32}[\'\"]')
	),

	Rule(
		'Incoming Webhooks from  Slack application ',
		'',
		'A7: XSS',
		Severity = "ERROR",
		CWE = "CWE-918: Server-Side Request Forgery (SSRF)",
		ExactMatch = re.compile(r'https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}')
	),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the Git code or repository. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
        ExactMatch = re.compile(r'(password\s*=\s*[\'|\"](.*)+[\'|\"])|(pass\s*=\s*[\'|\"](.*)+[\'|\"]\s)|(pwd\s*=\s*[\'|\"](.*)+[\'|\"]\s)|(passwd\s*=\s*[\'|\"](.*)+[\'|\"]\s)|(senha\s*=\s*[\'|\"](.*)+[\'|\"])')
	),

	Rule(
		'File contains sensitive information written directly, such as usernames, passwords, keys, etc.',
		'Credentials must not be stored in the git code or repository, an attacker could decompile the application and obtain the credential. There are ‘Secrets Management’ solutions that can be used to store secrets or use Pipeline resources.',
		'A3: Sensitive Data Exposure',
		Severity = "ERROR",
		CWE = "CWE-312: Cleartext Storage of Sensitive Information",
		ExactMatch = re.compile(r'-----BEGIN CERTIFICATE-----')
	)
]