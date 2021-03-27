import re

# EvidenceSample
class Warning:
    def __init__(self, line, column, content):
        self.Line = line
        self.Column = column
        self.Content = content

class InputFile:
    def __init__(self, filename):
        self.Filename = filename
        self.load()

    def load(self):
        try:
            with open(self.filename) as f:
                self.Content = f.read()
        except IOError:
            print("Fail to open file ", self.filename)
            exit(0)

        # Match new line
        newlineFinder = re.compile("\x0a")

        # Record positions of all lines
        indexes = [(m.start(0), m.end(0)) for m in newlineFinder.finditer(self.Content)]
        self.NewLineIndexes = [idx[0] for idx in indexes]

    # CollectEvidenceSample
    def Record(self, index):
        line, column = self.findLineAndColumn(index)

        if line < 0:
            print("Unexpected error in engine/file.py/record, line not found")
            exit(0)

        if line == 0:
            start = 0
        else:
            start = self.NewLineIndexes[line - 1]
        end = self.NewLineIndexes[line]
        lineContent = self.Content[start:end].replace("\r","").replace("\n","")

        return Warning(line, column, lineContent)

    def findLineAndColumn(self, index):
        # Find line id
        line = -1

        # TODO: Replace with faster algorithm, like binary search
        for item, id in enumerate(self.NewLineIndexes):
            if item >= index:
                line = item
                break
        if line == -1:
            return -1, -1

        lastline = max(0, lid-1)
        column = index - self.NewLineIndexes[lastline]

        return line, column