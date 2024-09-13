<!--toc:start-->
- [!.生成LLVM IR](#生成llvm-ir)
- [@.LLVM IR语法](#llvm-ir语法)
<!--toc:end-->

# !.生成LLVM IR
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
# @.LLVM IR语法

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
每个LLVM文件都定义了Module,每个Module包含一系列函数

