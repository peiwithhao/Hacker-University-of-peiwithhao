from urllib.parse import urlparse
from fuzzingbook.Fuzzer import fuzzer
import random
from mutation_zero import mutate

def http_program(url: str) -> bool:
    supported_schemes = ["http", "https"]
    result = urlparse(url)
    if result.scheme not in supported_schemes:
        raise ValueError("Scheme must be one of "+repr(supported_schemes))
    if result.netloc == '':
        raise ValueError("Host must be non-empty")
    return True

def is_valid_url(url: str) -> bool:
    try:
        result = http_program(url)
        return True
    except ValueError as e:
        return False

seed_input = "http://peiwithhao.github.io/search?q=fuzzing"
valid_inputs = set()
trails = 20
for i in range(trails):
    inp = mutate(seed_input)
    if is_valid_url(inp):
        valid_inputs.add(inp)

print(len(valid_inputs)/trails)
