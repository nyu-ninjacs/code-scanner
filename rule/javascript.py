from rule import Rule
import re

JavascriptRules = [
    Rule('Passing untreated parameters to queries in the database can cause an SQL injection, or even a NoSQL query injection.',
        '',
        ExactMatch = re.compile(r'\.(find|drop|create|explain|delete|count|bulk|copy).*\n*{.*\n*\$where(?:\'|"|):.*(?:req\.|req\.query|req\.body|req\.param)')),
    Rule('Test, remove it later',
         'test',
         ExactMatch = re.compile(r'req'))
]
