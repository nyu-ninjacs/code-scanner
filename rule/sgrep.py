import json
from io import StringIO

from semgrep import semgrep_main, util
from semgrep.constants import OutputFormat
from semgrep.output import OutputHandler, OutputSettings

from file import InputFile
from sast import *

class SGrep():
    def __init__(self, ruleset):
        self.ruleset = ruleset
        util.set_flags(False, True, False)
        try:
            self.setting = OutputSettings(
                output_format = OutputFormat.JSON,
                output_destination = None,
                error_on_findings = False,
                verbose_errors = False,
                strict = False,
                timeout_threshold = 3,
                json_stats = False,
                # json_time = False,
                output_per_finding_max_lines_limit = None,
            )
        except:
            self.setting = OutputSettings(
                output_format = OutputFormat.JSON,
                output_destination = None,
                error_on_findings = False,
                verbose_errors = False,
                strict = False,
                timeout_threshold = 3,
                json_stats = False,
                json_time = False,
                output_per_finding_max_lines_limit = None,
            )

    def Scan(self, filepath):
        self.io_capture = StringIO()
        
        self.output = OutputHandler(self.setting, stdout=self.io_capture)

        semgrep_main.main(
            output_handler = self.output,
            target = [filepath],
            jobs = 1,
            pattern=None,
            lang=None,
            configs=[self.ruleset],
            timeout=5,
            timeout_threshold = 3,
        )
        self.output.close()
        return self.format(filepath)
    
    def format(self, filepath):
        result = json.loads(self.io_capture.getvalue())
        issues = []
        for find in result['results']:
            i = Issue(Info(find['extra']['message'], ""), find['start']['line'], 
                           find['start']['col'], find['extra']['lines'],
                           lineEnd = find['end']['line'],
                           filename = filepath,
                           owasp = find['extra']['metadata']['owasp'], 
                           cwe = find['extra']['metadata']['cwe'], 
                           severity = find['extra']['severity'])
            issues.append(i)
        return issues