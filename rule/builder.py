import re
from rule.javascript import JavascriptRules

class RuleBuilder:

    def __init__(self):
        pass

    def Build(self, languages):
        return {
            'Javascript' : JavascriptRules
        }
        