import random

def fuzzer(max_length: int = 100, start_char: int = 32, char_range: int = 32):
    string_length = random.randrange(0, max_length+1)
    out = ""
    for i in range(0, string_length):
        out += chr(random.randrange(start_char, start_char + char_range))
    return out

content = fuzzer()
print(content)

