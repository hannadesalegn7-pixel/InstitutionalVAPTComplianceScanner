import sys
import os
import json

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from scanner.scanner import scan_target

print(json.dumps(scan_target(sys.argv[1])))