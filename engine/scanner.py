import os
from result import Result
from file import InputFile
from sast import *

# TODO: ADD rules()

languages = {
    ".js" : "Javascript",
    ".ts" : "Javascript",
    ".java" : "Java",
    ".py" : "Python"
    #  Support other languages
}
class Scanner:
    def __init__(self, filename, ruleBuilder):
        self.filename = filename
        self.ruleBuilder = ruleBuilder
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
        ruleSet = ["core", languages[ext]]
        rules = self.ruleBuilder.Build(ruleSet)

        self.result.Issues = AnalyzeFile(code, rules)

        return self.result