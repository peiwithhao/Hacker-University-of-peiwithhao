import matplotlib.pyplot as plt
import numpy as np
MAX = 1000
MIN = -MAX

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

print(calculate_distance(274, 153))
xx = np.outer(np.linspace(-10, 10, 30), np.ones(30))
yy = xx.copy().T
zz = calculate_distance(xx, yy)

fig = plt.figure()
ax = plt.axes(projection='3d')

ax.plot_surface(xx, yy, zz, cmap=plt.cm.jet, rstride=1, cstride=1, linewidth=0);
plt.show()
