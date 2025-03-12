import matplotlib.pyplot as plt
import numpy as np
import random
MAX = 10000
MIN = -MAX
LOG_VALUES = 20

def test_me(x, y):
    if x==2*(y+1):
        return True
    else:
        return False

def neighbors(x, y):
    return [(x+dx, y+dy) for dx in [-1, 0, 1]
            for dy in [-1, 0, 1]
            if (dx != 0 or dy !=0)
            and ((MIN <= x+dx <= MAX)
                 and(MIN <= y+dy <= MAX))]

def calculate_distance(x, y):
    return abs(x - 2*(y+1))

def test_me_instrumented(x, y):
    global distance
    distance = calculate_distance(x, y)
    if x == 2 * (y + 1):
        return True
    else:
        return False

def get_fitness(x, y):
    global distance
    test_me_instrumented(x, y)
    fitness = distance
    return fitness


def hillclimber():
    # Create and evaluate starting point
    x, y = random.randint(MIN, MAX), random.randint(MIN, MAX)
    fitness = get_fitness(x, y)
    print("Initial value %d, %d at fitness %.4f" % (x, y, fitness))
    iterations = 0
    logs = 0

    while fitness > 0:
        iterations += 1
        for nx, ny in neighbors(x, y):
            new_fitness = get_fitness(nx, ny)
            if new_fitness < fitness:
                x, y = nx, ny
                fitness = new_fitness
                if logs < LOG_VALUES:
                    print("New value: %d, %d at fitness %.4f" % (nx, ny, fitness))
                elif logs == LOG_VALUES:
                    print("...")
                logs += 1
                break
    print("Found optimum after %d iterations at %d, %d" % (iterations, x, y))


def steepest_ascent_hillclimber():
    # Create and evaluate starting point
    x, y = random.randint(MIN, MAX), random.randint(MIN, MAX)
    fitness = get_fitness(x, y)
    print("Initial value %d, %d at fitness %.4f" % (x, y, fitness))
    iterations = 0
    logs = 0

    while fitness > 0:
        iterations += 1
        for nx, ny in neighbors(x, y):
            new_fitness = get_fitness(nx, ny)
            if new_fitness < fitness:
                x, y = nx, ny
                fitness = new_fitness
                if logs < LOG_VALUES:
                    print("New value: %d, %d at fitness %.4f" % (nx, ny, fitness))
                elif logs == LOG_VALUES:
                    print("...")
                logs += 1
    print("Found optimum after %d iterations at %d, %d" % (iterations, x, y))

def test_me2(x, y):
    if(x * x == y * y * (x % 20)):
        return True
    else:
        return False

def test_me2_instrumented(x, y):
    global distance
    distance = abs(x * x - y * y * (x % 20))
    if(x * x == y * y * (x % 20)):
        return True
    else:
        return False

def bad_fitness(x, y):
    global distance
    test_me2_instrumented(x, y)
    fitness = distance
    return fitness

def restarting_hillclimber(fitness_function):
    data = []
    
    #Create and evaluate starting point
    x, y = random.randint(MIN, MAX), random.randint(MIN, MAX)
    fitness = fitness_function(x, y)
    data += [fitness]
    print("Initial value: %d, %d at fitness %.4f" % (x, y, fitness))
    iterations = 0

    # Stop once we have found an optimal solution
    while fitness > 0:
        changed = False
        iterations += 1
        # Move to first neighbor with a better fitness
        for (nx, ny) in neighbors(x, y):
            new_fitness = fitness_function(nx, ny)
            if new_fitness < fitness:
                x, y = nx, ny
                fitness = new_fitness
                data += [fitness]
                changed = True
                break
        if not changed:
            x, y = random.randint(MIN, MAX), random.randint(MIN, MAX)
            fitness = fitness_function(x, y)
            data += [fitness]
    print("Found optimum after %d iterations at %d, %d" % (iterations, x, y))
    fig = plt.figure()
    ax = plt.axes()
    xs = range(len(data))
    ax.plot(xs, data)
    plt.show()


restarting_hillclimber(bad_fitness)

