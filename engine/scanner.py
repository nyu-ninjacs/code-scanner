import os
from result import Result
from file import InputFile
from sast import *

languages = {
    ".js" : "Javascript",
    ".ts" : "Javascript",
    ".java" : "Java",
    ".py" : "Python",
    ".cs" : "Csharp"
}
class Scanner:
    def __init__(self, filename, ruleBuilder, sgrep_helper):
        self.filename = filename
        self.ruleBuilder = ruleBuilder
        self.sgrep_helper = sgrep_helper
        self.result = Result()

    def Scan(self):
        # Get language by file extension
        _, ext = os.path.splitext(self.filename)

        if not ext in languages:
            print(ext, " is currently not supported")
            exit(0)

        code = InputFile(self.filename)
        self.result.Size = len(code.Content)
        self.result.Lines = len(code.NewLineIndexes)

        # Set up rule sets to be used
        if languages[ext] == "Javascript":
            ruleSet = ["Core"]
        else:
            ruleSet = ["Core", languages[ext]]
        rules = self.ruleBuilder.Build(ruleSet)

        self.result.Issues = AnalyzeFile(code, rules)
        if languages[ext] == "Javascript":
            self.result.Issues += self.sgrep_helper.Scan(self.filename)

        return self.result