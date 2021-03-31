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
        ExactMatch = re.compile(r'\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:\'|"|):.*(?:req\.|req\.query|req\.body|req\.param)')),

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
        )
]
