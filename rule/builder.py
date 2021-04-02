import re
from core import CoreRules
from python import PythonRules
from csharp import CsharpRules
from javascript import JavascriptRules

class RuleBuilder:

    def __init__(self):
        pass

    def Build(self, languages):
        rules = []
        for language in languages:
            if language == 'Core':
                rules += CoreRules 
            elif language == 'Javascript':
                rules += JavascriptRules
            elif language == 'Csharp':
                rules += CsharpRules
            elif language == 'Python':
                rules += PythonRules
        return rules
        