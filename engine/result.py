from sast import Issue, Info

def sort_issue(i):
    return i.Line, i.Column

class Result:
    def __init__(self):
        self.Lines = 0
        self.Size = 0
        self.Issues = []

    def ReportConsole(self):
        self.Issues.sort(key=sort_issue)
        print("Lines: ", self.Lines)
        print("File size: ", self.Size, "\n")

        print("Vulnerabilities : ")
        for issue in self.Issues:
            info = issue.Info
            print("---------------------------------------")
            print("Description: ", info.Description)
            print("At Line {}, Column {}:".format(issue.Line, issue.Column))
            print(issue.Content)
            print(" "*max(0, issue.Column-1)+"^")
            #print("Recommendation: ", info.Recommendation)
            print("Severity: ", issue.Severity)
            print("OWASP", issue.OWASP)
            print(issue.CWE)