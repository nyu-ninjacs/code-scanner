from scanner import Scanner

class Engine:
    def __init__(self, ruleBuilder):
        self.ruleBuilder = ruleBuilder

    def Scan(self, filename):
        scanner = Scanner(filename, self.ruleBuilder)
        return scanner.Scan()