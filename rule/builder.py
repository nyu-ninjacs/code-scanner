import re
from rule.javascript import JavascriptRules

class RuleBuilder:

    def __init__(self):
        pass

    def Build(self, languages):
        rules = []
        for language in languages:
            if(language == 'Javascript'):
                rules += JavascriptRules
        return rules