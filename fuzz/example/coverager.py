from fuzzingbook.Fuzzer import * 
from fuzzingbook.Coverage import *

trails = 100

def population_coverage(population: List[str], function: Callable) \
        -> Tuple[Set[Location], List[int]]:
    cumulative_coverage: List[int] = []
    all_coverage: Set[Location] = set()

    for s in population:
        with Coverage() as cov:
            try:
                function(s)
            except:
                pass
        all_coverage |= cov.coverage()
        cumulative_coverage.append(len(all_coverage))

    return all_coverage, cumulative_coverage

def hundred_inputs() -> List[str]:
    population = []
    for i in range(trails):
        population.append(fuzzer())
    return population

all_coverage, cumulative_coverage = \
        population_coverage(hundred_inputs(), cgi_decode)

# %matplotlib inline

import matplotlib.pyplot as plt

plt.plot(cumulative_coverage)
plt.title('Coverage of cgi_decode() with random inputs')
plt.xlabel('# of inputs')
plt.ylabel('lines covered')
plt.show()




