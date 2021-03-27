from rule import Rule
class Info:
    def __init__(self, desc, title, recom):
        self.Description = desc
        self.Title = title
        self.Recommendation = recom

class Issue:
    def __init__(self, vid, line, info, col, content):
        self.VulnerabilityID = vid
        self.Line = line
        self.Info = info
        self.Column = col
        self.Content = content

def AnalyzeFile(inputFile, rules):
    issues = []
    for rule in rules:
        rule_issue = rule.Match(inputFile)
        if len(rule_issue) > 0:
            issues = issues + rule_issue
    return issues