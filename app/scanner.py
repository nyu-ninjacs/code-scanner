from engine import Engine
from builder import RuleBuilder
from sgrep import SGrep
from os import listdir
from os.path import isfile, join

import jsonpickle

def scan(filename):
    eng = Engine(RuleBuilder(), SGrep("../rule/sgrep_rules"))
    fname = filename
    filename = "../testdata/" + filename
    result = eng.Scan(filename)
    f = open(filename + "_scan_result.txt", "w")
    json_str = jsonpickle.encode(result)
    f.write(json_str)
    f.close()
    return fname

def scan_directory(dirname):
    print(dirname)
    files = [dirname + "/" + f for f in listdir(dirname) if isfile(join(dirname, f))]
    dirname = dirname.split('/')[-1]
    print(files)
    eng = Engine(RuleBuilder(), SGrep("../rule/sgrep_rules"))
    results = []
    filename = "../testdata/" + dirname
    f = open( filename + "_scan_result.txt", "w")
    for name in files:
        print("Filename: " + name)
        result = eng.Scan(name)
        results.append(result)
    json_str = jsonpickle.encode(results)
    f.write(json_str)
    f.close()
    return dirname