from engine import Engine
from builder import RuleBuilder
from sgrep import SGrep

import jsonpickle

def scan(filename):
    eng = Engine(RuleBuilder(), SGrep())
    fname = filename
    filename = "../testdata/" + filename
    result = eng.Scan(filename)
    f = open(filename + "_scan_result.txt", "w")
    json_str = jsonpickle.encode(result)
    f.write(json_str)
    f.close()
    return fname