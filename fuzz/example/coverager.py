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


# once

trials = 100
import matplotlib.pyplot as plt

runs = 100

sum_coverage = [0] * trails

for run in range(runs):
    all_coverage, coverage = population_coverage(hundred_inputs(), cgi_decode)
    assert len(coverage) == trails
    for i in range(trails):
        sum_coverage[i] += coverage[i]

average_coverage = []
for i in range(trails):
    average_coverage.append(sum_coverage[i] / runs)


plt.plot(average_coverage)
plt.title('Average of cgi_decode() with random inputs')
plt.xlabel('# of inputs')
plt.ylabel('lines covered')
plt.show()


