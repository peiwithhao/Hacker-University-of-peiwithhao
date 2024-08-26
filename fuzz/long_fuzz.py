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
                            universal_newline=True)
    runs.append((data, result))

