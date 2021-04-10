import re
from sast import Info
from file import InputFile
from sast import Issue

def run_rule(inputFile, finder, rule, info, fn):
    issues = []
    results = finder.finditer(inputFile.Content)

    for result in results:
        foundedContent = inputFile.Content[result.start():result.end()]

        if fn:
            reportIssue = fn(foundedContent, rule)
            if not reportIssue:
                return issues
        evidence = inputFile.Record(result.start(0))
        i = Issue(info, evidence.Line, evidence.Column, evidence.Content)
        issues.append(i)
    return issues

def run_and_rule(inputFile, rule, info):
    all_issues = []
    for expr in rule.And:
        issues = run_rule(inputFile,expr, rule, info, None)
        if len(issues) == 0:
            return issues
        all_issues += issues
    return all_issues

class Rule:

    def __init__(self, Description, Recommendation, Category, ExactMatch = None, And = [], NotOr = []):
        self.Description = Description
        self.Recommendation = Recommendation
        self.Category = Category
        self.ExactMatch = ExactMatch
        self.And = And
        self.NotOr = NotOr
    
    def Match(self, inputFile):
        info = Info(self.Description, self.Recommendation)
        if self.IsAndMatch():
            return run_and_rule(inputFile, self, info)
        elif self.IsMatch():
            return run_rule(inputFile, self.ExactMatch, self, info, None)
        return []

    def IsMatch(self):
        return self.ExactMatch != None
    
    def IsAndMatch(self):
        return len(self.And) != 0
