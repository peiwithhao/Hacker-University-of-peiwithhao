from fuzzingbook.Fuzzer import Runner
from fuzzingbook.MutationFuzzer import *
# 该类用于执行函数,判断成功/失败来返回集合
class FunctionRunner(Runner):
    def __init__(self, function: callable) -> None:
        """Initialize"""
        self.function = function
    def run_function(self, inp: str) -> any:
        return self.function(inp)
    def run(self, inp: str) -> tuple[any, str]:
        try:
            result = self.run_function(inp)
            outcome = self.PASS
        except Exception:
            result = None
            outcome = self.FAIL
        return result, outcome

from fuzzingbook.Coverage import Coverage, population_coverage, Location
# 该类继承了FunctionRunner,用来查看执行覆盖率
class FunctionCoverageRunner(FunctionRunner):
    def run_function(self, inp:str) -> any:
        with Coverage() as cov:
            try:
                result = super().run_function(inp)
            except Exception as exc:
                self._coverage = cov.coverage()
                raise exc
        self._coverage = cov.coverage()
        return result
    def coverage(self) -> set[Location]:
        return self._coverage

# 该类用来对于
class MutationCoverageFuzzer(MutationFuzzer):
    def reset(self) -> None:
        super().reset()
        self.coverages_seen: set[frozenset] = set()
        self.population = []
    def run(self, runner: FunctionCoverageRunner) -> any:
        result, outcome = super().run(runner)
        new_coverage = frozenset(runner.coverage())
        if outcome == Runner.PASS and new_coverage not in self.coverages_seen:
            self.population.append(self.inp)
            self.coverages_seen.add(new_coverage)
        return result       

http_runner = FunctionCoverageRunner(http_program)
seed_input = "http://www.google.com/search?q=fuzzing"
mutation_fuzzer =  MutationCoverageFuzzer(seed=[seed_input])
mutation_fuzzer.runs(http_runner, trials=10000)
print(mutation_fuzzer.population)

all_coverage, cumulative_coverage = population_coverage(
    mutation_fuzzer.population, http_program)

import matplotlib.pyplot as plt
plt.plot(cumulative_coverage)
plt.title('Coverage of urlparse() with random inputs')
plt.xlabel('# of inputs')
plt.ylabel('lines covered')
plt.show()
