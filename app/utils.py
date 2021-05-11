from datetime import datetime
from collections import defaultdict
import hashlib
import json
import time
import os
import re
import ast
import unicodedata
import jsonpickle

from werkzeug.routing import BaseConverter
from result import Result
from sast import Issue


_punctuation_re = re.compile(r'[\t !"#$%&\'()*\-/<=>?@\[\\\]^_`{|},.]+')


class RegexConverter(BaseConverter):

    def __init__(self, url_map, *items):
        super(RegexConverter, self).__init__(url_map)
        self.regex = items[0]


def read_file(file_path):
    """Read a file in an unicode safe way."""
    with open(file_path, 'rb') as file_ptr:
        return file_ptr.read().decode('utf-8', 'replace')


def issha2(data):
    """Check for a SHA2 string match."""
    return re.match('^[0-9a-f]{64}$', data)


def python_list(value):
    """Convert a list like string to a Python list."""
    if not value:
        value = []
    if isinstance(value, list):
        return value
    return ast.literal_eval(value)


def python_dict(value):
    """Convert a dict like string to Python dict."""
    if not value:
        value = {}
    if isinstance(value, dict):
        return value
    return ast.literal_eval(value)

def reconstruct(filename):
    filename = "../testdata/" + filename
    f = open(filename + "_scan_result.txt", "r")
    result = jsonpickle.decode(f.read())
    print(result)
    return result

def get_metrics(res):
    """Get Severity and Issue counts."""
    issue_count = 0
    severity_dict = {
        'error': 0,
        'warning': 0,
        'info': 0,
    }
    for issue in res.Issues:
        issue_count += 1
        if issue.Severity.lower() in severity_dict:
            severity_dict[issue.Severity.lower()] += 1
    return severity_dict, issue_count

def get_issues(issues):
    res = []
    _id = 0
    for item in issues:
        new_dict = {}
        new_dict['id'] = str(_id)
        new_dict['description'] = item.Info.Description
        new_dict['recommendation'] = item.Info.Recommendation
        new_dict['loc'] = '[' + str(item.Line) + ', ' + str(item.LineEnd - 1) + ']'
        new_dict['line'] = item.Line
        new_dict['column'] = item.Column
        new_dict['text'] = item.Content
        new_dict['owasp'] = item.OWASP
        new_dict['severity'] = item.Severity
        new_dict['cwe'] = item.CWE
        new_dict['filename'] = item.Filename
        res.append(new_dict)
        _id += 1
    return res

def get_issues_dist(issues):
    res = defaultdict(lambda: 0)
    for issue in issues:
        res[issue.OWASP] += 1
    return res
        

def gen_sha256_hash(msg):
    """Generate the SHA256 hash of a message."""
    hash_object = hashlib.sha256(msg.encode('utf-8'))
    return hash_object.hexdigest()


def gen_sha256_file(path):
    """Generate the SHA 256 hash of a file."""
    blocksize = 64 * 1024
    sha = hashlib.sha256()
    with open(path, 'rb') as fptr:
        while True:
            data = fptr.read(blocksize)
            if not data:
                break
            sha.update(data)
    return sha.hexdigest()


def sha256_finding(find_dict):
    """Generate hash of the finding."""
    return gen_sha256_hash(json.dumps(find_dict, sort_keys=True))


def year():
    """Get the current year."""
    now = datetime.now()
    return now.year


def slugify(text, delim=u'-'):
    """Generates an slightly worse ASCII-only slug."""
    result = []
    for word in _punctuation_re.split(text.lower()):
        word = unicodedata.normalize(
            'NFKD', word).encode(
                'ascii', 'ignore').decode('utf-8')
        if word:
            result.append(word)
    return delim.join(result)


def deslugify(text):
    """Reverse Slugify."""
    normalized = ''
    items = text.split('_')
    for item in items:
        normalized += item.capitalize() + ' '
    return normalized


def js_escape(value):
    """Javascript XSS escapes."""
    return (value.replace('<', '\\u003c').
            replace('>', '\\u003e').
            replace('"', '\\u0022').
            replace('\'', '\\u0027').
            replace('`', '\\u0060').
            replace('(', '\\u0028').
            replace(')', '\\u0029').
            replace('{', '\\u007b').
            replace('}', '\\u007d').
            replace('-', '\\u002d').
            replace('+', '\\u007d').
            replace('$', '\\u0024').
            replace('/', '\\u002f'))


def is_safe_path(safe_root, check_path):
    """Detect Path Traversal."""
    safe_root = os.path.realpath(os.path.normpath(safe_root))
    check_path = os.path.realpath(os.path.normpath(check_path))
    return os.path.commonprefix([check_path, safe_root]) == safe_root


def get_timestamp():
    """Get timestamp."""
    return datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d %H:%M:%S')
