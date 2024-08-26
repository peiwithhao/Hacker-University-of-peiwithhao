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




# Reference
[The Fuzzing Book](https://www.fuzzingbook.org/)
