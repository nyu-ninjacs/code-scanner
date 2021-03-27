from sast import Issue, Info
class Result:
    def __init__(self):
        self.Lines = 0
        self.Size = 0
        self.Issues = []

    def ReportConsole(self):
        print(self.Lines, " lines analyzed")
        print("Total length: ", self.Size)

        print("Vulnerabilities : ")
        for issue in self.Issues:
            info = issue.Info
            print("---------------------------------------")
            print("Issue {} at Line {}, Column {}:".format(issue.VulnerabilityID, issue.Line, issue.Column))
            print(issue.Content)
            print(" "*issue.Column+"^")
            print("Description: ", info.Description)
            print("Recommendation: ", info.Recommendation)

