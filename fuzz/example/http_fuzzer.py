from urllib.parse import urlparse
from fuzzingbook.Fuzzer import fuzzer

def http_program(url: str) -> bool:
    supported_schemes = ["http", "https"]
    result = urlparse(url)
    if result.scheme not in supported_schemes:
        raise ValueError("Scheme must be one of "+repr(supported_schemes))
    if result.netloc == '':
        raise ValueError("Host must be non-empty")
    return True


for i in range(1000):
    try:
        url = fuzzer(char_start = 32, char_range=96)
        result = http_program(url)
        print("Success!")
    except ValueError as e:
        pass


