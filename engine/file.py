import re

# EvidenceSample
class Warning:
    def __init__(self, line, column, content, lineEnd):
        self.Line = line
        self.Column = column
        self.Content = content
        self.LineEnd = lineEnd

class InputFile:
    def __init__(self, filename):
        self.Filename = filename
        self.load()

    def load(self):
        try:
            with open(self.Filename) as f:
                self.Content = f.read()
        except IOError:
            print("Fail to open file ", self.Filename)
            exit(0)

        # Match new line
        newlineFinder = re.compile("\x0a")

        # Record positions of all lines
        self.NewLineIndexes = [m.start(0) for m in newlineFinder.finditer(self.Content)]

    # CollectEvidenceSample
    def Record(self, start_index, end_index):
        line, column = self.findLineAndColumn(start_index)
        lineEnd,_ = self.findLineAndColumn(end_index)
        if line < 0:
            print("Unexpected error in engine/file.py/record, line not found")
            exit(0)

        if line == 0:
            start = 0
        else:
            start = self.NewLineIndexes[line - 1]
        end = self.NewLineIndexes[lineEnd]
        lineContent = self.Content[start:end].replace("\r","").replace("\n","")

        return Warning(line+1, column, lineContent, lineEnd+1)

    def findLineAndColumn(self, index):
        # Find line id
        line = -1

        # TODO: Replace with faster algorithm, like binary search
        for i, idx in enumerate(self.NewLineIndexes):
            if idx >= index:
                line = i
                break

        if line == -1:
            return -1, -1
        
        if line == 0:
            column = index
        else:
            lastline = max(0, line-1)
            column = index - self.NewLineIndexes[lastline]

        return line, column