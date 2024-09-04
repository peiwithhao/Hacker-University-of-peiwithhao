import random
def delete_random_character(s):
    # Returns s with a random bit delete in a random position
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    return s[:pos] + s[pos + 1:]

def insert_random_character(s):
    # Returns s with a random bit inserted in a random position
    pos = random.randint(0, len(s) - 1)
    random_character = chr(random.randrange(32, 127))
    return s[:pos + 1] + random_character + s[pos + 1:]

def flip_random_character(s):
    # Returns s with a random bit flipped in a random position
    if s == "":
        return s
    pos = random.randint(0, len(s) - 1)
    c = s[pos]
    bit = 1 << random.randint(0, 6)
    new_c = chr(ord(c) ^ bit)
    return s[:pos] + new_c + s[pos + 1:]

def mutate(s: str) -> str:
    mutators = [
            delete_random_character,
            insert_random_character,
            flip_random_character,
            ]
    mutators = random.choice(mutators)
    return mutators(s)

seed_input = "awesome peiwithhao fuzzing"
for i in range(10):
    print(repr(mutate(seed_input)))


