from scanner import Scanner

class Engine:
    def __init__(self, ruleBuilder, sgrep_helper):
        self.ruleBuilder = ruleBuilder
        self.sgrep_helper = sgrep_helper

    def Scan(self, filename):
        result = Scanner(filename, self.ruleBuilder).Scan()
        result.Issues += self.sgrep_helper.Scan(filename)
        return result