from engine import Engine
from file import *
from sast import  *
import re

class FakeRule:
    def Match(self, input):
        issues = []
        for m in self.finder.finditer(input.Content):
            warning = input.Record(m.start(0))
            issue = Issue(self.info, warning.Line, warning.Column, warning.Content)
            issues.append(issue)
        return issues

class FakeRule1(FakeRule):
    def __init__(self):
        self.finder = re.compile("def")
        self.info = Info("Find def", "test1", "no recommendation")

class FakeRule2(FakeRule):
    def __init__(self):
        self.finder = re.compile("\[.*\]")
        self.info = Info("Find []", "test2", "ninjacs!")

class FakeRuleBuilder:
    def Build(self, languages):
        return [FakeRule1(), FakeRule2()]

eng = Engine(FakeRuleBuilder())
result = eng.Scan("file.py")
result.ReportConsole()