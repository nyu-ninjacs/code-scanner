import sys
sys.path.append(r'./engine')
sys.path.append(r'./rule')

from engine import Engine

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 ninjacs.py [filename]")
        exit(0)

    # Replace 0 with rule builder
    eng = Engine(0)
    result = eng.Scan(argv[1])
    result.ReportConsole()