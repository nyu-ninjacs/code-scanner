import re
from engine.sast import Info

class Rule:

    def __init__(self, description, title, recommendation):
        self.description = description
        self.recommendation = recommendation
    
def Match(self, rule, inputFile):
    info = Info(rule.description, rule.recommendation)
    
