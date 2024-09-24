<!--toc:start-->
- [Fuzzing](#fuzzing)
  - [Random](#random)
    - [Fuzzers](#fuzzers)
    - [Runners](#runners)
  - [简易Fuzzer](#简易fuzzer)
  - [Fuzzing 外部的程序](#fuzzing-外部的程序)
    - [创建输入文件](#创建输入文件)
    - [激活外部程序](#激活外部程序)
    - [持续性Fuzzing](#持续性fuzzing)
  - [Fuzzing所寻找的Bugs](#fuzzing所寻找的bugs)
    - [缓冲区溢出](#缓冲区溢出)
    - [检查缺失](#检查缺失)
  - [捕获Errors](#捕获errors)
    - [检查内存访问](#检查内存访问)
- [Code Coverage](#code-coverage)
- [变异mutation](#变异mutation)
  - [覆盖率指导变异](#覆盖率指导变异)
- [灰盒模糊测试](#灰盒模糊测试)
  - [Power Schedules能力调度](#power-schedules能力调度)
  - [升级灰盒测试](#升级灰盒测试)
- [基于搜索的模糊测试](#基于搜索的模糊测试)
  - [测试复杂程序](#测试复杂程序)
  - [条件判断](#条件判断)
    - [全局变量](#全局变量)
    - [临时变量](#临时变量)
    - [辅助函数](#辅助函数)
- [Reference](#reference)
<!--toc:end-->

# Fuzzing
## Random
首先我们知道Fuzz就是一系列随机的输入,乱拳打死老师傅,以这样的手法来测试出程序的漏洞,接下来我们通过`The Fuzzing Book`来了解其中的本质
首先我们可以去下载他的代码来作为安装包,这里没推荐`pip install`是因为我的笔记本是archlinux,其中一般推荐用`pacman -S python-*`来进行安装,但无论是官方仓库还是AUR都没找到,
因此我就决定直接dump他的[python代码](https://www.fuzzingbook.org/dist/fuzzingbook-code.zip)测试路径下进行实验


### Fuzzers

首先我们可以来看看随机数的一个生成例子,fuzz()函数作为Fuzzer对象的一个方法用来产生一个字符串式的输入
下面是利用部分
```python
>>> from fuzzingbook.Fuzzer import RandomFuzzer
>>> random_fuzzer = RandomFuzzer()
>>> random_fuzzer.fuzz()
'-8=5 #&>02%3<1222&7="6++*)0$&\'.3>!$5>.(6?4 */$92\'*-0+1\'5.:-.+<"==+"$.,"#6+2..>,/'
>>> print(RandomFuzzer.__init__.__doc__)
Produce strings of `min_length` to `max_length` characters
           in the range [`char_start`, `char_start` + `char_range`)
>>> random_fuzzer = RandomFuzzer(min_length=10, max_length=20, char_start=65, char_range=26)
>>> random_fuzzer.fuzz()
'QMAGKIMLGYXDHASAYOZX'
```

### Runners
一个Fuzzer经常需要搭配一个Runner用来将fuzz的字符串来作为输入,他的结果是一类标准的状态和一个结果(包括PASS, FAIL 或者UNRESOLVED)
一个`PrintRunner`对象将会简单的打印给出的输入和结果

```python
>>> from fuzzingbook.Fuzzer import PrintRunner
>>> print_runner = PrintRunner()
>>> random_fuzzer.run(print_runner)
IJKRONWCQPRKMRYPB
('IJKRONWCQPRKMRYPB', 'UNRESOLVED')
```
一个`ProgramRunner`会将生成的输入给到外部的程序当中,他的返回值是一个程序状态(完成程序的实例)和结果(PASS, FAIL或者UNRESOLVED)

```python
>>> from fuzzingbook.Fuzzer import ProgramRunner
>>> cat = ProgramRunner('cat')
>>> random_fuzzer.run(cat)
(CompletedProcess(args='cat', returncode=0, stdout='LANHOJZPJBZDWYFB', stderr=''), 'PASS')
```
## 简易Fuzzer

我们既然有了到了random input的概念,那是不是可以自行写一个`fuzz()`函数呢,
答案当然是可以的,
```python
import random
def fuzzer(max_length: int = 100, start_char: int = 32, char_range: int = 32):
    string_length = random.randrange(0, max_length+1)
    out = ""
    for i in range(0, string_length):
        out += chr(random.randrange(start_char, start_char + char_range))
    return out

content = fuzzer()
print(content)
```
## Fuzzing 外部的程序
### 创建输入文件
```python
>>> import os
>>> import tempfile
>>> from fuzzingbook.Fuzzer import *
>>> basename = "input.txt"
>>> tempdir = tempfile.mkdtemp()
>>> FILE = os.path.join(tempdir,basename)
>>> print(FILE)
/tmp/tmpfsds7b5v/input.txt
>>> data = fuzzer()
>>> fd = open(FILE, "w")
>>> fd.write(data)
90
>>> fd.close()
>>> contents = open(FILE).read()
>>> print(contents)
717?,#*=*6=) 406#989$,"3,*->%%1;0;"9!93$=77'3.&+7/-',->,>)*7&-)//:4''172$3=3712/%$%66;&*5$717?,#*=*6=) 406#989$,"3,*->%%1;0;"9!93$=77'3.&+7/-',->,>)*7&-)//:4''172$3=3712/%$%66;&*5$
```


### 激活外部程序
现在我们有了输入文件,我们该选择目标程序作为受害者,这里使用计算器金车能够,我们看看异常的输入会导致他发生什么奇怪的事情
但我们首先先测试一下正常的输入

```python
>>> import os
>>> import subprocess
>>> program = "bc"
>>> FILE = "./testfile"
>>> fd = open(FILE, "w")
>>> data = "2+2\n"
>>> fd.write(data)
4
>>> fd.close()
>>> result = subprocess.run([program, FILE], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,stderr=subprocess.PIPE,universal_newlines=True)
>>> result.stdout
'4\n'
>>> result.returncode
0
```
### 持续性Fuzzing
现在我们持续性输入各种input到我们测试的程序当中看他是否会崩溃，我们可以将所有的输入数据和真实返回值成对存储在一起
```python

trails = 100
program = 'bc'

runs = []

for i in range(trails):
    data = fuzzer()
    with open(FILE, "w") as f:
        f.write(data)
    result = subprocess.run([program, FILE], 
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            universal_newlines=True)
    runs.append((data, result))
```
这段代码将输入100次给我们的进程然后得到对应的返回值后组队输入到runs数组当中，然后我们可以查看runs数组中的情况，我们会发现得出正常的结果次数极少，而这在fuzz当中又恰好是正常的

然后我们可以在后面查看我们的错误信息
```python
errors = [(data, result) for (data, result) in runs if result.stderr !="" ]
(first_data, first_rsault) = errors[0]
print(repr(first_data))
print(first_result.stderr)
```
在我自己机器上的测试如下:
```sh
'>&7=>4&86)2/79),>.594 7<7<<>9:$&#8? $<423>%&%>&0-1=$#.2 $#66<?)  /#/#"8-</9/>-=6\'=$(>+2'
./input.txt 1: syntax error
./input.txt 1: syntax error
./input.txt 1: syntax error
./input.txt 1: illegal character: :
./input.txt 1: illegal character: $
```

那么runs数组中会有除了`illgal character, parse error, or syntax error`还会有其他有意思的东西吗，比如说你发现的crash或者bug?
很遗憾并不多
```python
[result.stderr for (data, result) in runs if result.stderr != ""
 and "illegal character" not in result.stderr
 and "parse error" not in result.stderr
 and "syntax error" not in result.stderr]
```
那么我们如何来改善这种情况呢？欲知后事如何，请看下回分解。

## Fuzzing所寻找的Bugs


### 缓冲区溢出
这里不必多说，我们可以利用fuzz来模拟一下拥有缓冲区溢出漏洞的场景

```python

import os
import subprocess
from fuzzingbook.Fuzzer import *
from fuzzingbook.ExpectError import ExpectError
def crash_if_too_long(s):
    buffer = "pwh"
    if len(s) > len(buffer):
        raise ValueError

crash_if_too_long("awesome peiwithhao!")
```
这里传入一个大的字符串会立刻导致出现ValueError

```sh
Traceback (most recent call last):
  File "/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/bugs_finder.py", line 10, in <module>
    crash_if_too_long("awesome peiwithhao!")
  File "/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/bugs_finder.py", line 8, in crash_if_too_long
    raise ValueError
ValueError
```
同样可以采取fuzz的输入如下

```python
trails = 100
with ExpectError():
    for i in range(trails):
        s = fuzzer()
        crash_if_too_long(s)
```
### 检查缺失
许多程序没有异常检查,取而代之的则是函数返回的状态码,比如getchar()和读文件中读到文件末尾返回的EOF
那么如果我们的进行了一个非预期的输入呢,下面一个例子是模仿程序获取输入,但是如果字符过长会导致空转

```python

def hang_if_no_space(s):
    i = 0
    while True:
        if i < len(s):
            if s[i] == ' ':
                break
        i += 1
```
但我们可以使用timeout技巧来解决这一点,当接受时间过长就会爆出异常,如下:

```python
trials = 100
with ExpectTimeout(2):
    for i in range(trials):
        s = fuzzer()
        hang_if_no_space(s)
```
## 捕获Errors
### 检查内存访问
我们可以在编译参数中添加`-fsanitize=address`来在运行过程中检查越界错误
有如下代码:
```c
# clang -fsanitize=address -g -o sanitize sanitize.c
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    /* Create an array with 100 bytes, initialized with 42 */
    char *buf = malloc(100);
    memset(buf, 42, 100);

    /* Read the N-th element, with N being the first command-line argument */
    int index = atoi(argv[1]);
    char val = buf[index];

    /* Clean up memory so we don't leak */
    free(buf);
    return val;
}
```
这里可以看到有一个明显的越界漏洞,然后当我们输入一个大于100(当然熟悉glibc中内存分配源码的小伙伴会知道这里是不严谨的,但是为了形象就干脆这么说了)的值就会导致越界访问,然后sanitize就会打印以下内容

```shell
=================================================================
==15608==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x50b0000000ae at pc 0x5b7bbc40db7c bp 0x7ffd3e7a0f70 sp 0x7ffd3e7a0f68
READ of size 1 at 0x50b0000000ae thread T0
    #0 0x5b7bbc40db7b  (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x15fb7b) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a)
    #1 0x729655dfae07  (/usr/lib/libc.so.6+0x25e07) (BuildId: 98b3d8e0b8c534c769cb871c438b4f8f3a8e4bf3)
    #2 0x729655dfaecb  (/usr/lib/libc.so.6+0x25ecb) (BuildId: 98b3d8e0b8c534c769cb871c438b4f8f3a8e4bf3)
    #3 0x5b7bbc2d9064  (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x2b064) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a)

0x50b0000000ae is located 10 bytes after 100-byte region [0x50b000000040,0x50b0000000a4)
allocated by thread T0 here:
    #0 0x5b7bbc3c5149  (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x117149) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a)
    #1 0x5b7bbc40daef  (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x15faef) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a)
    #2 0x729655dfae07  (/usr/lib/libc.so.6+0x25e07) (BuildId: 98b3d8e0b8c534c769cb871c438b4f8f3a8e4bf3)
    #3 0x729655dfaecb  (/usr/lib/libc.so.6+0x25ecb) (BuildId: 98b3d8e0b8c534c769cb871c438b4f8f3a8e4bf3)
    #4 0x5b7bbc2d9064  (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x2b064) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a)

SUMMARY: AddressSanitizer: heap-buffer-overflow (/home/peiwithhao/repo/Hacker-University-of-peiwithhao/fuzz/example/fsanitize+0x15fb7b) (BuildId: a8df777576759904cf221029ee48948f8a8c7b2a) 
Shadow bytes around the buggy address:
  0x50affffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50affffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50afffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50afffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x50b000000000: fa fa fa fa fa fa fa fa 00 00 00 00 00 00 00 00
=>0x50b000000080: 00 00 00 00 04[fa]fa fa fa fa fa fa fa fa fa fa
  0x50b000000100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x50b000000300: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==15608==ABORTING
```

# Code Coverage
如名字所言就是你这个异常input进去,代码所执行的条目覆盖情况,fuzzingbook也提供了对应的类别供我们使用

其利用`sys.settrace(f)`来对函数`f()`来进行跟踪,具体情况如下
```python

def traceit(frame: FrameType, event: str, arg: Any) -> Optional[Callable]:
    """Trace program execution. To be passed to sys.settrace()."""
    if event == 'line':
        global coverage
        function_name = frame.f_code.co_name
        lineno = frame.f_lineno
        coverage.append(lineno)

    return traceit


def cgi_decode_traced(s: str) -> None:
    global coverage
    coverage = []
    sys.settrace(traceit)  # Turn on
    cgi_decode(s)
    sys.settrace(None)    # Turn off
```
这里不得不赞叹一下python这个语言的便携性,对于函数的追踪显得如此简便

我们也可以以覆盖率的大小作为标准来判定input的有效性,然后不断迭代我们的input来达到最高的覆盖率,我们可以使用fuzzingbook提供的python库来进行实验

```python
>>> from fuzzingbook.Fuzzer import *
>>> from fuzzingbook.Coverage import *
>>> sample = fuzzer()
>>> sample
'3)!(7\'<34#+7=":2--:'
>>> with Coverage() as cov_fuzz:
...     try:
...             cgi_decode(sample)
...     except:
...             pass
... 
'3)!(7\'<34# 7=":2--:'
>>> cov_fuzz.coverage()
{('cgi_decode', 218), 
 ('cgi_decode', 231), 
 ('cgi_decode', 215), 
 ('cgi_decode', 211), 
 ('cgi_decode', 208), 
 ('cgi_decode', 214), 
 ('cgi_decode', 230), 
 ('cgi_decode', 217), 
 ('cgi_decode', 207), 
 ('cgi_decode', 220), 
 ('cgi_decode', 210), 
 ('cgi_decode', 216), 
 ('cgi_decode', 229), 
 ('cgi_decode', 219), 
 ('cgi_decode', 209)}
```

而我们的`cgi_decode`在文件中的行数是位于200~231的,这里明显有没有走到的地方

接下来我们编写输入循环,来测量最大覆盖率的输入

```python

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
```

然后我们最终所生成的图如下
![fuzz coverage](/home/peiwithhao/Pictures/screen_print/2024-09-01-21-18-22.png)

可以看到在我们输入20~40次的时候,程序整体的覆盖率已经达到最大,
然后我们可以查看多次测试下,随机输入的平均次数如下:

![multi fuzz](img/Figure_1.png)

这里拿其他类型语言的程序举例,例如C语言
我们可以直接在编译器上面添加相对应参数就可以生成记录覆盖率的文件,例如gcc的就是`-ftest_coverage`


# 变异mutation
这里以url作为本章的例子,我们知道一个url具有以下格式
```
scheme://netloc/path?query#fragment
```
解析上述字段:
+ `scheme`:将要用到的协议
+ `etloc`:主机名
+ `path`:主机下的路径
+ `query`:一个键值对
+ `fragment`:接受文档的一个标记，例如章节名等

我们可以通过python的urlparse类来轻松进行解析
```python
>>> from urllib.parse import urlparse
>>> urlparse("stp://peiwithhao.github.io/search?catgory=LinuxKernel")
ParseResult(scheme='stp', netloc='peiwithhao.github.io', path='/search', params='', query='catgory=LinuxKernel', fragment='')
```

下面写一个小小的url检测工具,然后来fuzz它

```python

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
```

但为了得到正确的反馈,就必须scheme字段为http/https,并且主机名不能为空,在fuzzingbook网站上作者进行了一个小小的计算,最终得出的结果是需要几个月到一年的时间才几乎可能得到一个符合程序的fuzzer输入,那么我们该如何解决这种问题呢,接下来就引入变异输入的概念


所谓变异就是就是对你的输入进行一个细微的修改,例如插入/删除/反转一位等等
下面给出这几种例子

```python
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
```

其中结果大致如下:
```sh
'awesome peiwithahao fuzzing'
'awesome peiwithhao fuzzi0ng'
'awesome peiwkthhao fuzzing'
'awesome peiwithhao fuzzinf'
'aesome peiwithhao fuzzing'
'awesome peiwathhao fuzzing'
'awesome peiwithhao uzzing'
'wesome peiwithhao fuzzing'
'awesome peiwithlao fuzzing'
'awEesome peiwithhao fuzzing'
```
而我们的变异就可以从一个真正能成功输入的字符串当中开始输入,然后不断变异这个字符串

```python
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
trails = 20
for i in range(trails):
    inp = mutate(seed_input)
    if is_valid_url(inp):
        valid_inputs.add(inp)
```

那么我们fuzz多少次才能得到http->https的变异呢,我们可以使用下面的程序测试一下
```sh
❯ python3 http_mutation_fuzzer.py
Success after 5240 trials in 0.005960848999166046 seconds
```
而上面的代码只能进行一次异变,除此之外我们可以进行一次输入多次变异,这样可以大大增加他的变异范围和速度

## 覆盖率指导变异
这里的大概思路就是在出现了覆盖率的变化时就将触发的输入就放入population集合,然后之后的input就基于这个population集合进行变异

# 灰盒模糊测试
我会好奇除了白盒和黑盒,灰盒是什么东西,gpt给出的结果如下:
> Greybox fuzzing（灰盒模糊测试）是一种软件测试技术，结合了黑盒测试和白盒测试的特点。它在测试过程中对目标程序的内部结构有一定的了解，但并不完全掌握。这种方法通常用于发现软件中的安全漏洞和缺陷。在灰盒模糊测试中，测试工具可以利用一些关于程序内部状态的信息（例如代码路径、变量值等），以生成更有效的测试用例。这种方法的优势在于，它能够比纯粹的黑盒测试更有效地覆盖代码路径，同时又不需要像白盒测试那样对程序的所有细节有深入的了解。

而AFL(American Fuzzing Lop)就是一种灰盒fuzz工具,该工具的常用方法是将输入的种子做微小的修改,或者是将一个输入的前半部分和另一个人输入的后半部分拼接起来

AFL可以利用覆盖率的反馈来学习如何在测试一个程序中达到更大的覆盖率
+ 其不是一个完全的黑盒的原因是AFL的使用需要至少有一点程序分析
+ 其不是一个完全的白盒的原因是AFL不基于重量级程序分析或约束解决方案
+ 其使用轻巧的程序工具来手机有关生成输入的覆盖率.如果说生成的输入增加了覆盖率,他将会被添加到种子语料库

这里开始讲解`fuzzingbook/GreyboxFuzzer.py`中的代码

```python

class Mutator:
    """Mutate strings"""

    def __init__(self) -> None:
        """Constructor"""
        self.mutators = [
            self.delete_random_character,
            self.insert_random_character,
            self.flip_random_character
        ]
```
上述代码定义了拥有三种变异对象的集合

```python

class Mutator(Mutator):
    def insert_random_character(self, s: str) -> str:
        """Returns s with a random character inserted"""
        pos = random.randint(0, len(s))
        random_character = chr(random.randrange(32, 127))
        return s[:pos] + random_character + s[pos:]
```
上述代码定义了一个重写类型,并且定义了其中的插入随机字符串的函数,和我们之前写的类似,然后其余两种变异函数也是以同样的方法进行插入,最后有一个总的类型

```python
class Mutator(Mutator):
    def mutate(self, inp: Any) -> Any:  # can be str or Seed (see below)
        """Return s with a random mutation applied. Can be overloaded in subclasses."""
        mutator = random.choice(self.mutators)
        return mutator(inp)
```
这里我们发现是随机分配一个变异器然后进行变异

## Power Schedules能力调度
这里介绍一个新的定义-Power Schedules,该指标的作用是用来给在populations集合当中的seeds来分配宝贵的fuzzing时间
而我们的目标就是**通过最大化那些极具潜力的种子seeds所占用的fuzzing时间来在最短时间达到最大的覆盖率增长速度**

而从population集合中选择seeds的可能性被称之为种子的`energe`
在整个模糊测试的过程当中,我们需要优先考虑更有希望的种子.
简单来讲我们不想要将精力浪费在不那么有潜力的seeds上面.而这个决策的过程就被称为Power Schedules.

例如AFL将把更多的energe分配给短的,执行快的,更大覆盖率增长的种子

然后来看看`fuzzingbook`所实现的`PowerSchedule`
```python
class PowerSchedule:
    """Define how fuzzing time should be distributed across the population."""

    def __init__(self) -> None:
        """Constructor"""
        self.path_frequency: Dict = {}

    def assignEnergy(self, population: Sequence[Seed]) -> None:
        """Assigns each seed the same energy"""
        for seed in population:
            seed.energy = 1

    def normalizedEnergy(self, population: Sequence[Seed]) -> List[float]:
        """Normalize energy"""
        energy = list(map(lambda seed: seed.energy, population))
        sum_energy = sum(energy)  # Add up all values in energy
        assert sum_energy != 0
        norm_energy = list(map(lambda nrg: nrg / sum_energy, energy))
        return norm_energy

    def choose(self, population: Sequence[Seed]) -> Seed:
        """Choose weighted by normalized energy."""
        self.assignEnergy(population)
        norm_energy = self.normalizedEnergy(population)
        seed: Seed = random.choices(population, weights=norm_energy)[0]
        return seed
```

上述代码中的choose()简而言之就是首先将population集合中的seed的energe至1,然后遍历列表获取他的百分数作为norm_energe,然后来选择种子
可以使用下面的命令测试
```python
>>> from fuzzingbook.GreyboxFuzzer import Mutator
>>> from fuzzingbook.Coverage import Location
>>> from fuzzingbook.GreyboxFuzzer import Seed
>>> from fuzzingbook.GreyboxFuzzer import PowerSchedule
>>> population = [Seed("A"), Seed("B"), Seed("C")]
>>> schedule = PowerSchedule()
>>> hits = {
...     "A":0,
...     "B":0,
...     "C":0
... }
>>> for i in range(1000):
...     seed = schedule.choose(population)
...     hits[seed.data]+=1
... 
>>> hits
{'A': 340, 'B': 348, 'C': 312}
```

其中发现击中数量大致一次

现在介绍以下基于增强变异的黑盒fuzzing,如下:
```python
class AdvancedMutationFuzzer(Fuzzer):
    """Base class for mutation-based fuzzing."""

    def __init__(self, seeds: List[str],
                 mutator: Mutator,
                 schedule: PowerSchedule) -> None:
        """Constructor.
        `seeds` - a list of (input) strings to mutate.
        `mutator` - the mutator to apply.
        `schedule` - the power schedule to apply.
        """
        self.seeds = seeds
        self.mutator = mutator
        self.schedule = schedule
        self.inputs: List[str] = []
        self.reset()

    def reset(self) -> None:
        """Reset the initial population and seed index"""
        self.population = list(map(lambda x: Seed(x), self.seeds))
        self.seed_index = 0

    def create_candidate(self) -> str:
        """Returns an input generated by fuzzing a seed in the population"""
        seed = self.schedule.choose(self.population)

        # Stacking: Apply multiple mutations to generate the candidate
        candidate = seed.data
        trials = min(len(candidate), 1 << random.randint(1, 5))
        for i in range(trials):
            candidate = self.mutator.mutate(candidate)
        return candidate

    def fuzz(self) -> str:
        """Returns first each seed once and then generates new inputs"""
        if self.seed_index < len(self.seeds):
            # Still seeding
            self.inp = self.seeds[self.seed_index]
            self.seed_index += 1
        else:
            # Mutating
            self.inp = self.create_candidate()

        self.inputs.append(self.inp)
        return self.inp
```

```python
>>> from fuzzingbook.Fuzzer import Fuzzer
>>> from fuzzingbook.GreyboxFuzzer import AdvancedMutationFuzzer
>>> seed_input = "good"
>>> mutation_fuzzer = AdvancedMutationFuzzer([seed_input], Mutator(), PowerSchedule())
>>> print(mutation_fuzzer.fuzz())
good
>>> print(mutation_fuzzer.fuzz())
Qg
>>> print(mutation_fuzzer.fuzz())
g}do4old
>>> print(mutation_fuzzer.fuzz())
oodZg
>>> print(mutation_fuzzer.fuzz())
#g^d
>>> print(mutation_fuzzer.fuzz())
l!od
```
## 升级灰盒测试
这里是指我们的power schedule将会为执行更加不寻常函数路径的seeds分配更多的energe

# 基于搜索的模糊测试
传说中的启发式来了,当我们在进行模糊测试的时候如果产生了某个idea,例如希望在程序中达到特殊的状态时,我们可以对其进行搜索,如果我们可以预估几个程序的输入中哪个更接近我们正在寻找的输入,那么此信息就可以被称之为启发式信息

那么首先我们需要确定该搜索空间的具体形象,例如说单个数值,数组或者说是XML文档
在本次的示例,使用以下代码
```python
>>> def test_me(x,y):
...     if x==2*(y+1):
...             return True
...     else:
...             return False
... 
>>> test_me(0, 0)
False
>>> test_me(7, 3)
False
>>> test_me(6, 2)
True
```
这样我们的输入被规范为(x, y),然后每个点都会拥有相邻的输入
```
x-1, y-1
x-1, y
x-1, y+1
x, y+1
x+1, y+1
x+1, y
x+1, y-1
x, y-1
```

然后这里定义一个获取相邻节点的函数
```python
def neighbors(x, y):
    return [(x+dx, y+dy) for dx in [-1, 0, 1]
            for dy in [-1, 0, 1]
            if (dx != 0 or dy !=0)
            and ((MIN <= x+dx <= MAX)
                 and(MIN <= y+dy <= MAX))]

print(neighbors(2,2))
```
打印以下内容
```sh
[(1, 1), (1, 2), (1, 3), (2, 1), (2, 3), (3, 1), (3, 2), (3, 3)]
```

所有的启发式功能都基与估计给定的候选解决方案有多良好,这里的"好"通常称为个体的和适度(fitness),并且估计这种和适度的被称为和适度函数(fitness function)

考虑到上面测试函数,现在给出他的fitness function 如下:
```python
def calculate_distance(x, y):
    return abs(x - 2*(y+1))

print(calculate_distance(274, 153))
``` 这样会输出34作为绝对距离,而该函数就作为我们的fitness function
![fitness](img/fitness.png)

现在拥有了适合度计算的函数,我们需要知道如何来获取最佳的适合度,

其中我们需要使用到名为`Hillclimbing`的算法来完成,这个算法很简单:
1. 随机选定一个起点
2. 计算该点的所有邻居的和适度
3. 移动到最佳和适度的邻居
4. 如果问题未解决,则继续步骤2

```python
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
                print("New value: %d, %d at fitness %.4f" % (x, y, fitness))
            elif logs == LOG_VALUES:
                print("...")
            logs += 1
            break
    print("Found optimum after %d iterations at %d, %d" % (iterations, x, y))

hillclimber()
```
不断选择最优节点,而这个函数实现是一旦找到最新更合适的neighbor则进行跳转,可以看到他的迭代次数是较多的

```sh
❯ python3 search_fuzzer.py
Initial value 971, -198 at fitness 1365.0000
New value: 970, -198 at fitness 1364.0000
New value: 969, -198 at fitness 1363.0000
New value: 968, -198 at fitness 1362.0000
New value: 967, -198 at fitness 1361.0000
New value: 966, -198 at fitness 1360.0000
New value: 965, -198 at fitness 1359.0000
New value: 964, -198 at fitness 1358.0000
New value: 963, -198 at fitness 1357.0000
New value: 962, -198 at fitness 1356.0000
New value: 961, -198 at fitness 1355.0000
New value: 960, -198 at fitness 1354.0000
New value: 959, -198 at fitness 1353.0000
New value: 958, -198 at fitness 1352.0000
New value: 957, -198 at fitness 1351.0000
New value: 956, -198 at fitness 1350.0000
New value: 955, -198 at fitness 1349.0000
New value: 954, -198 at fitness 1348.0000
New value: 953, -198 at fitness 1347.0000
New value: 952, -198 at fitness 1346.0000
New value: 951, -198 at fitness 1345.0000
...
Found optimum after 1365 iterations at -394, -198
```
那么现在我们若改为获取邻居中最小的再进行跳转呢
```python
❯ python3 search_fuzzer.py
Initial value 995, 521 at fitness 49.0000
New value: 994, 520 at fitness 48.0000
New value: 995, 520 at fitness 47.0000
New value: 996, 520 at fitness 46.0000
New value: 995, 519 at fitness 45.0000
New value: 996, 519 at fitness 44.0000
New value: 997, 519 at fitness 43.0000
New value: 996, 518 at fitness 42.0000
New value: 997, 518 at fitness 41.0000
New value: 998, 518 at fitness 40.0000
New value: 997, 517 at fitness 39.0000
New value: 998, 517 at fitness 38.0000
New value: 999, 517 at fitness 37.0000
New value: 998, 516 at fitness 36.0000
New value: 999, 516 at fitness 35.0000
New value: 1000, 516 at fitness 34.0000
New value: 999, 515 at fitness 33.0000
New value: 1000, 515 at fitness 32.0000
New value: 999, 514 at fitness 31.0000
New value: 1000, 514 at fitness 30.0000
New value: 999, 513 at fitness 29.0000
...
Found optimum after 22 iterations at 1000, 499
```
awesome!我们只迭代了22次就迭代到了最终解决方法
但是!我们不是每次fuzz都能如此顺利的使用hillclimbing算法来获取结果
因为我们可能面临下面一种情况,那就是我们当前节点的所有邻居都没有没有更好的和适度,如下面的函数
```python
test_me2(x, y):
    if(x * x = y * y * (x % 20)):
        return True
    else:
        return False
```
这种情况下最简单的办法就是重新开始,立刻从另一个随机数作为起点继续hillclimbing

```python
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
restarting_hillclimber(bad_fitness)
```
最终测试多次也基本位于100次左右
```sh
❯ python3 search_fuzzer.py
Initial value: -144, -97 at fitness 129808.0000
Found optimum after 99 iterations at -719, 719
```
然后我们调高MIN, MAX范围来画图
![restart_fitness](img/restart_fitness.png)
横轴data数组的下标,数轴则是该data元素的fitness值,而可以看到在最终趋于0的过程当中我们有多次的restarting

## 测试复杂程序
刚刚是演示了一个简单的例子,接下来将测试之前了解到的`cgi_decode`
我们按照上面的步骤,首先需要找到每一个输入的邻居
```python
def neighbor_strings(x):
    n = []
    for pos in range(len(x)):
        c = ord(x[pos])
        if c < 126:
            n += [x[:pos] + chr(c+1) + x[pos + 1:]]
        if c > 32:
            n += [x[:pos] + chr(c-1) + x[pos + 1:]]
    return n
```
这里是遍历每一个字符串当中的字符,然后按照ASCII码值来生成neighbors
这里设计出了得到neighbors的函数,接下来的步骤便是设计和适度检测的函数`fitness_function`

## 条件判断
上面的test_me()函数由一个单个if条件生成,而这里我们所测试的函数`cgi_decode()`则有好几个条件判断语句,也就是说我们的分支距离判断需要有好几种类型, 这里设置分支距离为目标字符距离我们规范数组里面字符的最近距离 如下:
### 全局变量
```python
def distance_character(target, values):
    # Initialize with very large value so that any comparison is better
    minimum = sys.maxsize
    for elem in values:
        distance = abs(target - elem)
        if distance < minimum:
            minimum = distance
    return minimum
```
### 临时变量
当我们处理复杂分支条件如`if A and B`时,这个条件的distance我们可以等价于这两者条件distance的和`distance_A + distance_B`,因为需要两者都为True才能进入条件
而当处理`if A or B`时,我们自然而然这个条件的distance是两者的较小值`MIN(distance_A, distance_B)`
因为我们只需要一个条件满足就可以进行下一部分

但是这在实际环境当中并不简单, 有点程序采用short-circuit评估标准,那就是在`A or B`的条件下,如果A为true,那么便不会执行B的判断,而如果说B是一个有着副作用的表达式,那么通过计算`short-curcuit`评估标准下的B的分支距离可能会导改变程序的行为,而这一行为是不能接受的

例子如下,有这样一个判断:
```
distance = abs(x - 2*foo(y))
if x == 2 * foo(y):
... 
```
如果我们照往常来设计instrument的话,那我们将执行foo()两次,而这两次的返回值很大概率是不同的,一个避免这个问题的方法就是转换这个判断条件例如可以将比较的值先暂存到临时变量,然后条件语句比较这两者

```python
tmp1 = x
tmp2 = 2 * foo(y)
distance = abs(tmp1 - tmp2)
if tmp1 == tmp2:
    ...
```
### 辅助函数
除了使用全局和临时变量的另一中方法是将时机比较替换为对辅助函数的调用, 这里给出例子
```python
def evaluate_condition(num, op, lhs, rhs):
    distance_true = 0
    distance_false = 0
    if op == "Eq":
        if lhs == rhs:
            distance_false = 1
        else:
            distance_true = abs(lhs - rhs)
    # ... code for other types of conditions
    if distance_true == 0:
        return True
    else:
        return False
```
可以看到分别传递操作码op, 和两个操作数lhs, rhs然后最后返回判断条件

但是上面的判断条件函数还没将运行时的distance进行记录,这样也导致我们无法通过fitnesss function来接近目标

由于被测试函数cgi_decode()存在多个条件判断,并且我们可能对其中的True和False都感兴趣,那么我们就可以创建True和False集合

```python
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
```
这里的变量`condition_num`是我们测量的条件唯一ID, 

# Reference
[The Fuzzing Book](https://www.fuzzingbook.org/)
[AFL Author's strategy](https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html)
