import os
import subprocess
from fuzzingbook.Fuzzer import *
trails = 100
program = 'bc'

runs = []

FILE = os.path.join("./", "input.txt")


for i in range(trails):
    data = fuzzer()
    with open(FILE, "w") as f:
        f.write(data)
    result = subprocess.run([program, FILE], 
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
    runs.append((data, result))
# sum(1 for (data, result) in runs if result.stderr == "")

errors = [(data, result) for (data, result) in runs if result.stderr !="" ]

[result.stderr for (data, result) in runs if result.stderr != ""
 and "illegal character" not in result.stderr
 and "parse error" not in result.stderr
 and "syntax error" not in result.stderr]

(first_data, first_result) = errors[0]
print(repr(first_data))
print(first_result.stderr)
