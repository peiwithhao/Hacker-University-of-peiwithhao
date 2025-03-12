import os
import subprocess
from fuzzingbook.Fuzzer import *
from fuzzingbook.ExpectError import ExpectError
from fuzzingbook.ExpectError import ExpectTimeout

def crash_if_too_long(s):
    buffer = "pwh"
    if len(s) > len(buffer):
        raise ValueError

def hang_if_no_space(s):
    i = 0
    while True:
        if i < len(s):
            if s[i] == ' ':
                break
        i += 1

trials = 100
with ExpectTimeout(2):
    for i in range(trials):
        s = fuzzer()
        hang_if_no_space(s)
