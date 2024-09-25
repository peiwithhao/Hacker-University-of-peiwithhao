import sys
import inspect
import ast
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
        distance_true == 0
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


source = inspect.getsource(cgi_decode)
node = ast.parse(source)
BranchTransformer().visit(node)

node = ast.fix_missing_locations(node)
print(ast.unparse(node))



