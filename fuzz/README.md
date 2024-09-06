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
- [变异](#变异)
  - [覆盖率指导变异](#覆盖率指导变异)
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


# 变异
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
# Reference
[The Fuzzing Book](https://www.fuzzingbook.org/)
[AFL Author's strategy](https://lcamtuf.blogspot.com/2014/08/binary-fuzzing-strategies-what-works.html)
