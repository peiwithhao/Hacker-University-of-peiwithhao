<!--toc:start-->
- [!.生成LLVM IR](#生成llvm-ir)
- [@.LLVM IR语法](#llvm-ir语法)
- [\#.LLVM IR内存模型](#llvm-ir内存模型)
- [$. IR层次优化](#ir层次优化)
  - [$.!. ImmutablePass class](#immutablepass-class)
  - [$.@. ModulePass class](#modulepass-class)
  - [$.\#. The CallgraphSCCPass class](#the-callgraphsccpass-class)
  - [$.$. FunctionPass class](#functionpass-class)
- [\%. LLVM Pass 编写](#llvm-pass-编写)
- [((.引用](#引用)
<!--toc:end-->

# 1.生成LLVM IR
用下列例子来说明如何将C代码转换为LLVM IR
```c
int sum(int a, int b){
    return a+b;
}
```
而IR在磁盘上可以以两种格式存在:bitcode格式或汇编文本
其中bitcode格式编译如下:
```sh
$ clang c2ir.c -emit-llvm -c -o c2ir.bc
```
而汇编文本格式如下:
```sh
$ clang c2ir.c -emit-llvm -S -c -o c2ir.ll
```

```llvm
; ModuleID = 'c2ir.c'
source_filename = "c2ir.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128
-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @sum(i32 noundef %0, i32 noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store i32 %1, ptr %4, align 4
  %5 = load i32, ptr %3, align 4
  %6 = load i32, ptr %4, align 4
  %7 = add nsw i32 %5, %6
  ret i32 %7
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointe
r"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-prot
ector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,
+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 18.1.8"}
```



其中我们的`.ll`文件也可以通过`llvm-as *.ll -o *.bc`命令来将其转换为bitcode
相反的也是一样`llvm-dis *.bc -o *.ll`

而`llvm-extract`工具还能提取IR函数/全局变量,还能从IR模块中删除全局变量,例如用下面的命令可以提取我们刚刚设置的函数sum:

```sh
$ llvm-extract -func=sum c2ir.bc -o c2ir.bc
```
# 2.LLVM IR语法

```LLVM
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128
-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @sum(i32 noundef %0, i32 noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store i32 %1, ptr %4, align 4
  %5 = load i32, ptr %3, align 4
  %6 = load i32, ptr %4, align 4
  %7 = add nsw i32 %5, %6
  ret i32 %7
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointe
r"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-prot
ector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,
+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
```
+ Module: 每个LLVM文件都定义了Module,每个Module包含一系列函数
+ 局部值: 是汇编语言中的寄存器的模拟, 以%符号为开头,后面跟值的名字
    + SSA:静态单赋值, 每个值只有一个单一赋值定义它,每次使用一个值可以直接向后追溯到给出定义的唯一指令,而SSA形式建立了平凡的use-def链条,也就是一个值到达使用之处的定义列表.
    + 三地址指令:数据处理指令有两个源操作数和一个目的操作数来存放结果 
    + 无限量寄存器:
+ 字段target datalayout包含target triple的字节顺序和类型长度信息,由target host描述
```LLVM
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128
-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"
```
+ 其中处理器一个运行linux-gnu的x86_64处理器,而由于layout的第一个字母为e则表明是小端序,大写E则表明是大端序列
+ 类型信息的格式为:`type:<size>:<abi>:<preferred>`,上述的表示

而函数声明类似于C语言
```LLVM
define dso_local i32 @sum(i32 noundef %0, i32 noundef %1) #0 {
```
这里表示函数返回一个i32类型的值,且有两个i32类型的参数,下面解释各个字段的含义:
+ dso_local: 表示该函数是`动态共享对象本地`的意思,意味着这个函数不会被导出到共享库当中,通常用于优化目的,表明该函数只在当前模块中使用
+ i32: 表示函数返回值类型
+ @sum: 函数的名称, @表示这是一个全局符号
+ i32 noundef %0: 这里是定义了一个类型为i32的参数,而noundef表示这个参数在调用时不能是未定义值 
这里给出LLVM广泛使用到的类型:
+ 任意长度的整数,表示形式:iN,通常有i32, i64, i128
+ 浮点类型,例如32为精度和64位精度浮点
+ 向量类型, 表示格式为<<\#elements>x<elementtype>>,例如,包含四个i32元素的向量为<4 x i32>

而函数声明中的标签\#0映射到一组函数属性,这个属性组可以在函数或其他定义中使用
```LLVM
attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointe
r"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-prot
ector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,
+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
```
下面解释字段内容:
+ noinline: 指示编译器不要内联该函数,即使这可能提高性能 nounwind: 表示该函数不会抛出异常
+ optnone: 指示编译器不对该函数进行任何优化
+ sspstrong: 表示启用强堆栈保护
+ uwtable: 表示该函数使用未定义行为表,通常用于异常处理
函数提被显示地划分为基本快(BB:basic block),标签(label)用于开始一个新的基本块

然而我发现我自行编译的函数并没有类似于`entry`这样的入口点,那么我重新编写函数尝试生成LLVM IR

接下来解析指令方面

```LLVM
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  store i32 %0, ptr %3, align 4
  store i32 %1, ptr %4, align 4
  %5 = load i32, ptr %3, align 4
  %6 = load i32, ptr %4, align 4
  %7 = add nsw i32 %5, %6
  ret i32 %7
```
+ alloca: 表示在当前函数的栈帧上预留空间,空间大小取决于元素类型的长度,通常表示局部变量
+ align 4: 表示该元素遵从4字节对齐
+ %3, %4: 表示指向这些占元素的而指针
+ store: 表示将%0的值存放在%3的位置,最后返回%7

而事实上这里的load和store是十分多于的,我们可以直接将函数参数进行加法返回,而clang默认使用-O0(无优化),不会消除无用的load和store,因此我们使用-O1,则编译情况如下
```LLVM
  %3 = add nsw i32 %1, %0
  ret i32 %3
```
# 3.LLVM IR内存模型
+ Module: 聚合整个翻译单元所用到的所有数据,声明了Module::iterator typedef,作为遍历这个模块中的函数的简便方法,可以用begin()和end()方法获取这些迭代器,可以在这些[Module API](https://llvm.org/doxygen/classllvm_1_1Module.html)查看
+ Function: 包含有关函数定义和声明的所有对象,对于声明来说,它仅包含函数圆形,无论定义或者声明,它都包含函数参数的列表,可以通过getArgumentList()方法或者arg_begin()和arg_end()这对方法来访问

+ BasicBlock: 封装LLVM指令序列, 可以通过begin()/end()来访问, 可以使用getTerminator()方法直接访问它的最后一条指令,还可以用一些辅助函数遍历CFG

+ Instruction: 表示LLVM IR的运算原子,一个单一的指令,他是一个User类的子类

根据中文文档所说,依托SSA形式,LLVM最强大的部分就是`Value和User接口`
这个接口可以让你能够轻松操作use-def和def-use链条.
在LLVM驻留内存的IR中,一个继承自Value的类意味着它定义饿了一个结果,可以被其他IR使用,而继承User的子类则意味着这个实体使用了一个或者多个Value的接口.
Function和Instruction同时是Value和User的子类,而BasicBlock只是Value的子类

+ Value: 定义use_begin()和use_end()方法,让您能够遍历各个User, 为访问它的def-use链条提供了轻松的方法,对于每个Value类,可以通过getName()方法访问它的名字.这个模型决定了任何LLVM Value都有一个和他关联的不同的标识. 例如, %add1可以标识一个加法指令的结果, BB1可以标识一个基本快, myfunc可以标识一个函数.Value还有一个强大的方法, 成为replaceAllUsersWith(Value *), 它遍历这个值的所有使用者,用某个其他的值替代他

+ User: User类定义了op_begin()和op_end()方法,让你能够快速访问所有它用到的Value接口,这里代表了use-def链条, 你也可以利用一个辅助函数,称之为replaceUsesOfWith(Value * From, Value *To),替换所有它用到的值,在[这里]https://llvm.org/doxygen/classllvm_1_1User.html)可以查看他的全部接口

# 4. IR层次优化
一旦我们构造出了LLVM IR,一个程序将受到各种各样的目标无关代码优化,优化可一次作用一个函数或一个模块

我们所编写的LLVM passes都是Pass类的子类,一般存在`CallGraphSCCPass, FunctionPass, LoopPass, RegionPass`类,而选择继承哪个类来向系统表明你编写的Pass想要做什么
下面介绍集中常见的类型

## 4.1. ImmutablePass class 
被称为最苍白和无聊得而类型, 通常表明该pass不是一定需要运行,不会改变状态并且绝不会被更新, 虽然这个pass类很少被使用,但是对于提供当前编译机器信息和起他可以影响动态翻译的静态信息来说是重要的,

## 4.2. ModulePass class
最普遍的一个类型,继承该类表明你的passs使用整个程序作为一个单元,以不可预测的顺序来引用函数体, 或添加和删除函数
要写一个正确的ModulePass class, 我们需要继承ModulePass 并且覆盖`runOnModule`方法

```pass
virtual bool runOnModule(Module &M) = 0;
```
该方法在模块被翻译修改后返回True, 其他情况则返回False

## 4.3. The CallgraphSCCPass class
通常被用来遍历程序从下到上的调用图,如果你编写的Pass符合以下的需求,并且不符合functionPass的需求,则应该继承CallGraphSCCPass
下面介绍一些方法:
`doInitialization(CallGraph &)method`
```c++
virtual bool doInitialization(CallGraph &);
```
该函数被允许做CallGraphSCCPass所不允许做的绝大多数事情, 能添加或移除函数,获取函数的指针等等

```c++
virtual bool runOnSCC(CallGraphSCC &SCC) = 0;
```
该函做一些pass的有趣工作,如果module被修改则返回True,否则返回false

```c++
virtual bool doFinalzation(CallGraph &CG) = 0;
```
该函不常用,只有当pass的框架完成了正在编译的程序中每个SCC的runOnSCC函数之后才会被调用

## 4.4. FunctionPass class
与ModulePass class相反, FunctionPassClass 的子类通常是可预测的

简单来说,该类不能做以下事情:
1. 检测或修改当前正在处理的函数以外的函数
2. 从当前模块添加或移除函数
3. 从当前模块添加或一处全局变量
4. 在runOnFunction(包括全局数据)的调用中保持状态

相关函数如下:
```c++
virtual bool doInitialization(CallGraph &);
```
被允许做FunctionPass所不允许做的绝大多数事情,能添加或者移除函数,获取指针等等

```c++
virtual bool runOnSCC(CallGraphSCC &SCC) = 0;
```
必须在子类做分析翻译工作的时候来运行
```c++
virtual bool doFinalzation(CallGraph &CG) = 0;
```
最后调用同上

# 5. LLVM Pass 编写 
首先下载github的库:


# 编译Linux内核
实际上只需要使用
```sh
$ make LLVM=1 -j<your cores_nr>
```
就可以正常编译

而如果我们想要获取LLVM IR的话需要一些额外操作
这里使用wllvm来作为提取工具

具体步骤如下,首先导出一个环境变量
```sh
$ export LLVM_COMPILER=clang
```
然后我们进入到下载到的linux源码目录
```c
make CC=clang defconfig # 默认配置
make CC=wllvm LLVM=1 #开始编译
```

# ((.引用
[LLVM-CORE](https://getting-started-with-llvm-core-libraries-zh-cn.readthedocs.io/zh-cn/latest/ch05.html)
[Value API](https://llvm.org/doxygen/classllvm_1_1Value.html)
[使用LLVM编译Linux内核](https://www.kernel.org/doc/html/latest/kbuild/llvm.html)
[llvm_bc不生成的解决方案](https://blog.csdn.net/ckugua/article/details/129502143)


