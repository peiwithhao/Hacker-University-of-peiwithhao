import sys
import inspect
import ast
from fuzzingbook.bookutils import print_content
def cgi_decode(s):
    """Decode the CGI-encoded string `s`:
       * replace "+" by " "
       * replace "%xx" by the character with hex number xx.
       Return the decoded string.  Raise `ValueError` for invalid inputs."""

    # Mapping of hex digits to their integer values
    hex_values = {
        '0': 0, '1': 1, '2': 2, '3': 3, '4': 4,
        '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
        'a': 10, 'b': 11, 'c': 12, 'd': 13, 'e': 14, 'f': 15,
        'A': 10, 'B': 11, 'C': 12, 'D': 13, 'E': 14, 'F': 15,
    }
    t = ""
    i = 0
    while i < len(s):
        c = s[i]
        if c == '+':
            t += ' '
        elif c == '%':
            digit_high, digit_low = s[i + 1], s[i + 2]
            i += 2
            if digit_high in hex_values and digit_low in hex_values:
                v = hex_values[digit_high] * 16 + hex_values[digit_low]
                t += chr(v)
            else:
                raise ValueError("Invalid encoding")
        else:
            t += c
        i += 1
    return t

def neighbor_strings(x):
    n = []
    for pos in range(len(x)):
        c = ord(x[pos])
        if c < 126:
            n += [x[:pos] + chr(c+1) + x[pos + 1:]]
        if c > 32:
            n += [x[:pos] + chr(c-1) + x[pos + 1:]]
    return n

def distance_character(target, values):
    # Initialize with very large value so that any comparison is better
    minimum = sys.maxsize
    for elem in values:
        distance = abs(target - elem)
        if distance < minimum:
            minimum = distance
    return minimum

def update_maps(condition_num, d_true, d_false):
    global distances_true, distances_false
    if condition_num in distances_true.keys():
        distances_true[condition_num] = min(distances_true[condition_num], d_true)
    else:
        distances_true[condition_num] = d_true
    if condition_num in distances_false.keys():
        distances_false[condition_num] = min(distances_false[condition_num], d_false)
    else:
        distances_false[condition_num] = d_false
        
def evaluate_condition(num, op, lhs, rhs):
    distance_true = 0
    distance_false = 0

    if isinstance(lhs, str):
        lhs = ord(lhs)
    if isinstance(rhs, str):
        rhs = ord(rhs)

    if op == "Eq":
        if lhs == rhs:
            distance_false = 1
        else:
            distance_true = abs(lhs - rhs)
    elif op == "Lt":
        if lhs < rhs:
            distance_false = abs(lhs - rhs)
        else:
            distance_true = lhs - rhs + 1
    elif op == "In":
        minimum = sys.maxsize
        for elem in rhs.keys():
            distance = abs(lhs - ord(elem))
            if distance < minimum:
                minimum = distance
        distance_true = minimum
        if distance_true == 0:
            distance_false = 1
    update_maps(num, distance_true, distance_false)

    # ... code for other types of conditions
    if distance_true == 0:
        return True
    else:
        return False

class BranchTransformer(ast.NodeTransformer):
    branch_num = 0
    def visit_FunctionDef(self, node):
        node.name = node.name + "_instrumented"
        return self.generic_visit(node)
    def visit_Compare(self, node):
        if node.ops[0] in [ast.Is, ast.IsNot, ast.NotIn]:
            return node
        self.branch_num += 1
        return ast.Call(func=ast.Name("evaluate_condition", ast.Load()),
                        args = [ast.Num(self.branch_num),
                                ast.Str(node.ops[0].__class__.__name__), 
                                node.left,
                                node.comparators[0]],
                        keywords = [],
                        starargs = None,
                        kwargs = None)


# source = inspect.getsource(cgi_decode)
# node = ast.parse(source)
# BranchTransformer().visit(node)
#
# node = ast.fix_missing_locations(node)
# print_content(ast.unparse(node), '.py')

from typing import Dict, cast

def create_instrumented_function(f):
    source = inspect.getsource(f)
    node = ast.parse(source)
    node = BranchTransformer().visit(node)

    # Make sure the line numbers are ok so that it compiles
    node = ast.fix_missing_locations(node)

    # Compile and add the instrumented function to the current module
    current_module = sys.modules[__name__]
    code = compile(cast(ast.Module, node), filename="<ast>", mode="exec")
    exec(code, current_module.__dict__)

# Initialize the global maps
distances_true: Dict[int, int] = {}
distances_false: Dict[int, int] = {}


# # Create the instrumented function
create_instrumented_function(cgi_decode)
# # check if the result has no changed    
# assert cgi_decode("Hello+reader%90") == cgi_decode_instrumented("Hello+reader%90")
# print(cgi_decode_instrumented("Hello+reader%90"))
# print(distances_true)
# print(distances_false)

def normalize(x):
    return x/(1.0 + x)

def get_fitness_cgi(x):
    # Reset any distance values from previous executions
    global distances_true, distances_false
    distances_true = {}
    distances_false = {}

    try:
        cgi_decode_instrumented(x)
    except BaseException:
        pass

    fitness = 0.0
    for branch in [1, 3, 4, 5]:
        if branch in distances_true:
            fitness += normalize(distances_true[branch])
        else:
            fitness += 1.0

    for branch in [2]:
        if branch in distances_false:
            fitness += normalize(distances_false[branch])
        else:
            fitness += 1.0
    return fitness

import random


def random_string(l):
    s = ""
    for i in range(l):
        random_character = chr(random.randrange(32, 127))
        s = s + random_character
    return s

def random_unicode_string(l):
    s = ""
    for i in range(l):
        random_character = chr(random.randrange(0, 65536))
        s = s + random_character
    return s

def unicode_string_neighbors(x):
    n = []
    for pos in range(len(x)):
        c = ord(x[pos])
        if c < 65536:
            n += [x[:pos] + chr(c - 1) + x[pos + 1:]]
        if c > 0:
            n += [x[:pos] + chr(c + 1) + x[pos + 1:]]
    return n


def hillclimb_cgi():
    x = random_string(10)
    fitness = get_fitness_cgi(x)
    print("Initial input: %s at fitness %.4f" % (x, fitness))

    while fitness > 0:
        changed = False
        for (nx) in neighbor_strings(x):
            new_fitness = get_fitness_cgi(nx)
            if new_fitness < fitness:
                fitness = new_fitness
                x = nx
                changed = True
                print("New value: %s at fitness %.4f" % (x, fitness))
                break
        if not changed:
            x = random_string(10)
            fitness = get_fitness_cgi(x)
    print("Optimum at %s, fitness %.4f" % (x, fitness))

from fuzzingbook.bookutils import unicode_escape, terminal_escape

def terminal_repr(s):
    return terminal_escape(repr(s))

LOG_VALUES = 10
def hillclimb_cgi_limited(max_iterations):
    x = random_unicode_string(10)
    fitness = get_fitness_cgi(x)
    print("Initial input: %s at fitness %.4f" % (terminal_repr(x), fitness))
    iteration = 0
    logs = 0

    while fitness > 0 and iteration < max_iterations:
        changed = False
        for (nx) in unicode_string_neighbors(x):
            new_fitness = get_fitness_cgi(nx)
            if new_fitness < fitness:
                fitness = new_fitness
                x = nx
                changed = True
                if logs < LOG_VALUES:
                    print("New value: %s at fitness %.4f" % (terminal_repr(x), fitness))
                elif logs == LOG_VALUES:
                    print("...")
                logs += 1
                break
        if not changed:
            x = random_string(10)
            fitness = get_fitness_cgi(x)
        iteration += 1
    print("Optimum at %s, fitness %.4f" % (terminal_repr(x), fitness))

def flip_random_character(s):
    pos = random.randint(0, len(s) - 1)
    new_c = chr(random.randrange(0, 65536))
    return s[:pos] + new_c + s[pos +1 :]


# 1+1 Evolutionary Algorithm 1+1EA
def randomized_hillclimb():
    x = random_unicode_string(10)
    fitness = get_fitness_cgi(x)
    print("Initial input: %s at fitness %.4f" % (terminal_repr(x), fitness))
    iterations = 0

    while fitness > 0:
        mutated = flip_random_character(x)
        new_fitness = get_fitness_cgi(mutated)
        if new_fitness <= fitness:
            fitness = new_fitness
            x = mutated
        iterations += 1
    print("Optimum at %s, fitness %.4f" % (x, fitness))

def create_population(size):
    return [random_unicode_string(10) for i in range(size)] 

def evaluate_population(population):
    fitness = [get_fitness_cgi(x) for x in population]
    return list(zip(population, fitness))

# 
def selection(evaluated_population, tournament_size):
    # 从evaluated_population 中选出tournament_size个
    competition = random.sample(evaluated_population, tournament_size)
    winner = min(competition, key=lambda individual: individual[1])[0]
    # return a copy of the selected individual
    return winner[:]

def crossover(parent1, parent2):
    pos = random.randint(1, len(parent1))
    offspring1 = parent1[:pos] + parent2[pos:]
    offspring2 = parent2[:pos] + parent1[pos:]
    return (offspring1, offspring2)

def mutate(chromosome):
    mutated = chromosome[:]
    P = 1.0 / len(mutated)
    for pos in range(len(mutated)):
        if random.random() < P:
            new_c = chr(int(random.gauss(ord(mutated[pos]), 100) % 65536))
            mutated = mutated[:pos] + new_c + mutated[pos + 1:]
    return mutated

def genetic_algorithm():
    # Generate and evaluate initial population
    generation = 0
    population = create_population(100)
    fitness = evaluate_population(population)
    best = min(fitness, key=lambda item: item[1])
    best_individual = best[0]
    best_fitness = best[1]
    print("Best fitness of initial population: %s - %.10f" %
        (terminal_repr(best_individual), best_fitness))
    logs = 0

    # Stop when optimum found, or we run out of patience
    while best_fitness > 0 and generation < 1000:

        # The next generation will have the same size as the current one
        new_population = []
        while len(new_population) < len(population):
            # Selection
            offspring1 = selection(fitness, 10)
            offspring2 = selection(fitness, 10)

            # Crossover
            if random.random() < 0.7:
                (offspring1, offspring2) = crossover(offspring1, offspring2)

            # Mutation
            offspring1 = mutate(offspring1)
            offspring2 = mutate(offspring2)

            new_population.append(offspring1)
            new_population.append(offspring2)

        # Once full, the new population replaces the old one
        generation += 1
        population = new_population
        fitness = evaluate_population(population)

        best = min(fitness, key=lambda item: item[1])
        best_individual = best[0]
        best_fitness = best[1]
        if logs < LOG_VALUES:
            print(
                "Best fitness at generation %d: %s - %.8f" %
                (generation, terminal_repr(best_individual), best_fitness))
        elif logs == LOG_VALUES:
            print("...")
        logs += 1

    print(
        "Best individual: %s, fitness %.10f" %
        (terminal_repr(best_individual), best_fitness))



genetic_algorithm()





