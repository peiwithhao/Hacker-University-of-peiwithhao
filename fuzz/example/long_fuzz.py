from ExpectError import ExpectError
trails = 100
program = 'bc'

runs = []

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

#查看正常输入
sum(1 for (data, result) in runs if result.stderr == "")

errors = [(data, result) for (data, result) in runs if result.stderr !="" ]
(first_data, first_reault) = errors[0]
print(repr(first_data))
print(first_result.stderr)


[result.stderr for (data, result) in runs if result.stderr != ""
 and "illegal character" not in result.stderr
 and "parse error" not in result.stderr
 and "syntax error" not in result.stderr]


def crash_if_too_long(s):
    buffer = "Thursday"
    if len(s) > len(buffer):
        raise ValueError

with ExpectError():
    for i in range(trails):
        s = fuzzer()
        crash_if_too_long(s)


