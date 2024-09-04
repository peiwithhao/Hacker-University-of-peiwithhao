from urllib.parse import urlparse
from fuzzingbook.Fuzzer import fuzzer
import random

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
        print("successfull")
        return True
    except ValueError as e:
        print(e)
        return False

assert is_valid_url("http://www.google.com/search?q=fuzzing")
assert not is_valid_url("xyzzy")
