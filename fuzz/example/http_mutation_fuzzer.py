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
trails = 0
# ============= single mutation =============
# from fuzzingbook.Timer import Timer
# with Timer() as t:
#     while True:
#         trails += 1
#         inp = mutate(seed_input)
#         if inp.startswith("https://"):
#             print(
#                     "Success after",
#                     trails,
#                     "trials in",
#                     t.elapsed_time(),
#                     "seconds"
#                     )
#             break
# ===============  multiple mutations ===========
# mutations = 50
# inp = seed_input
# for i in range(mutations):
#     if i % 5 == 0:
#         print(i, "mutations:", repr(inp))
#     inp = mutate(inp)

class MutationFuzzer(Fuzzer):
    """Base class for mutational fuzzing"""
    def __init__(self, seed: List[str],
                 min_mutations: int = 2,
                 max_mutations: int = 10) -> None:
        """Constructor
        `seed` - a list of input string to mutate
        `min_mutations` - the min num of mutations to apply
        `max_mutations` - the max num of mutations to apply
        """
        self.seed = seeds
        self.min_mutations = min_mutations
        self.max_mutations = max_mutations
        self.reset()
    def reset(self) -> None:
        """Set populations to initial seed.
        To be overloaded in subclassed. """
        self.population =  self.seed
        self.seed_index = 0

Class C(C):
    def new_method(self, args):
        pass



