import re
from engine.sast import Info
from engine.file import Record
from engine.sast import Issue

def run_rule(self, inputFile, finder, rule, info, fn):
    issues = []
    results = finder.finditer(pattern, inputFile.Content)
    if not results:
        return issues
    for result in results:
        foundedContent = inputFile.Content[result.start():result.end()]

        if fn:
            reportIssue = fn(foundedContent, rule)
            if not reportIssue:
                return issues
        evidence = Record(result[0])
        i = Issue(info, evidence.Line, evidence.Column, foundedContent)
        issues.append(i)
    return issues
    
def run_and_rule(self, inputFile, rule, info):
    all_issues = []
    for expr in rule.And:
        issues = run_rule(inputFile,expr, rule, info, None)
        if not issues:
            return issues
        all_issues += issues
    return all_issues

class Rule:

    def __init__(self, Description, Recommendation, ExactMatch = None, And = None):
        self.Description = Description
        self.Recommendation = Recommendation
        self.ExactMatch = ExactMatch
        if And is None:
            And = []
        self.And = And
    
    def Match(self, inputFile):
        issues = []
        info = Info(self.description, self.recommendation)
        if self.IsAndMatch:
            i = run_and_rule(inputFile, self, info)
            issues += i
        return issues

    def IsMatch(self):
        return self.ExactMatch != None
    
    def IsAndMatch(self):
        return len(self.And) != 0
