# xpdf

<!--toc:start-->
- [xpdf](#xpdf)
  - [environment](#environment)
  - [编译Xpdf](#编译xpdf)
  - [下载初始函数](#下载初始函数)
  - [fuzz](#fuzz)
<!--toc:end-->


## environment
OS: ubuntu20.04LTS
LLVM: 11
afl++: latest  
Xpdf: 3.02

## 编译Xpdf
首先使用afl-cc将Xpdf进行编译
```sh
wget https://dl.xpdfreader.com/old/xpdf-3.02.tar.gz
tar -xvzf xpdf-3.02.tar.gz
```
```sh
export LLVM_CONFIG="llvm-config-11"
CC=$HOME/AFLplusplus/afl-clang-fast CXX=$HOME/AFLplusplus/afl-clang-fast++ ./configure --prefix="$HOME/fuzzing_xpdf/install/"
make
make install
```

首先使用afl-cc 将该源代码进行编译,实际上我们只需要修改其中他的Makefile选项即刻

## 下载初始函数
这里我们可以随便下载几个pdf作为输入文件
```sh
cd $HOME/fuzzing_xpdf
mkdir pdf_examples && cd pdf_examples
wget https://github.com/mozilla/pdf.js-sample-files/raw/master/helloworld.pdf
wget http://www.africau.edu/images/default/sample.pdf
wget https://www.melbpc.org.au/wp-content/uploads/2017/10/small-example-pdf-file.pdf
```

## fuzz
简单的设置input和output文件夹即可
```sh
afl-fuzz -i $HOME/fuzzing_xpdf/pdf_examples/ -o $HOME/fuzzing_xpdf/out/ -s 123 -- $HOME/fuzzing_xpdf/install/bin/pdftotext @@ $HOME/fuzzing_xpdf/output
```
最终当屏幕出现crash时我们就可以从`output/default/crashes/*`寻找到我们的crash输入,这里表现为全是pdf

然后我们就可以启动gdb和利用该输入来进行分析
最后通过backtrace发现存在一个循环调用

```pwndbg
#8  0x00005555555f6cb8 in XRef::fetch (this=0x555555693230, num=7, gen=0, obj=0x7fffff7ff2f0) at XRef.cc:823
#9  0x00005555555dfa2f in Object::dictLookup (this=0x7fffff7ff4b0, obj=0x7fffff7ff2f0, key=0x55555560a1c6 "Length") at Object.h:253
#10 Parser::makeStream (this=this@entry=0x555556ceda50, dict=dict@entry=0x7fffff7ff4b0, fileKey=fileKey@entry=0x0, encAlgorithm=encAlgorithm@entry=cryptRC4, keyLength=keyLength@entry=0, 
    objNum=objNum@entry=7, objGen=0) at Parser.cc:156
#11 0x00005555555dffb8 in Parser::getObj (this=this@entry=0x555556ceda50, obj=obj@entry=0x7fffff7ff4b0, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=objNum@entry=7, objGen=<optimized out>)
    at Parser.cc:94
#12 0x00005555555f6cb8 in XRef::fetch (this=0x555555693230, num=7, gen=0, obj=0x7fffff7ff4b0) at XRef.cc:823
#13 0x00005555555dfa2f in Object::dictLookup (this=0x7fffff7ff670, obj=0x7fffff7ff4b0, key=0x55555560a1c6 "Length") at Object.h:253
#14 Parser::makeStream (this=this@entry=0x555556ced570, dict=dict@entry=0x7fffff7ff670, fileKey=fileKey@entry=0x0, encAlgorithm=encAlgorithm@entry=cryptRC4, keyLength=keyLength@entry=0, 
    objNum=objNum@entry=7, objGen=0) at Parser.cc:156
#15 0x00005555555dffb8 in Parser::getObj (this=this@entry=0x555556ced570, obj=obj@entry=0x7fffff7ff670, fileKey=0x0, encAlgorithm=cryptRC4, keyLength=0, objNum=objNum@entry=7, objGen=<optimized out>)
    at Parser.cc:94
```
可以看到栈的结构是`Parser::getObj->Parser::makeStream->Object::dictLookup->XRef::fetch->Parser::getObj`

下载xpdf4.02进行diff可以发现进行了修改
![getObj](/home/peiwithhao/Pictures/screen_print/2024-09-30-00-07-09.png)
![XRef](/home/peiwithhao/Pictures/screen_print/2024-09-30-00-07-38.png)


