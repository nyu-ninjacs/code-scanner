from rule import Rule
class Info:
    def __init__(self, desc, recom):
        self.Description = desc
        self.Recommendation = recom

class Issue:
    def __init__(self, info, line, col, content):
        self.Info = info
        self.Line = line
        self.Column = col
        self.Content = content

def AnalyzeFile(inputFile, rules):
    issues = []
    for rule in rules:
        rule_issue = rule.Match(inputFile)
        if len(rule_issue) > 0:
            issues = issues + rule_issue
    return issues