; ModuleID = 'test.c'
source_filename = "test.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [17 x i8] c"func_a is here \0A\00", align 1
@.str.1 = private unnamed_addr constant [17 x i8] c"func_b is here \0A\00", align 1
@global_a = dso_local global i64 0, align 8
@global_static_b = internal global i64 1, align 8
@.str.2 = private unnamed_addr constant [3 x i8] c"%d\00", align 1
@.str.3 = private unnamed_addr constant [7 x i8] c"Nice!\0A\00", align 1
@.str.4 = private unnamed_addr constant [9 x i8] c"No Nice\0A\00", align 1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @func_a() #0 {
  %1 = call i32 (ptr, ...) @printf(ptr noundef @.str)
  ret void
}

declare i32 @printf(ptr noundef, ...) #1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @func_b() #0 {
  %1 = call i32 (ptr, ...) @printf(ptr noundef @.str.1)
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @asmlike() #0 {
  call void asm sideeffect "push %rax;pop %rdi;mov %rax, 39;syscall;", "~{dirflag},~{fpsr},~{flags}"() #3, !srcloc !6
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  store i64 1, ptr @global_a, align 8
  store i64 2, ptr @global_static_b, align 8
  store i32 0, ptr %2, align 4
  %4 = call i32 (ptr, ...) @__isoc23_scanf(ptr noundef @.str.2, ptr noundef %2)
  %5 = load i32, ptr %2, align 4
  %6 = icmp eq i32 %5, 16
  br i1 %6, label %7, label %29

7:                                                ; preds = %0
  %8 = call i32 (ptr, ...) @__isoc23_scanf(ptr noundef @.str.2, ptr noundef %2)
  %9 = load i32, ptr %2, align 4
  %10 = icmp eq i32 %9, 17
  br i1 %10, label %11, label %28

11:                                               ; preds = %7
  %12 = call i32 (ptr, ...) @__isoc23_scanf(ptr noundef @.str.2, ptr noundef %2)
  %13 = load i32, ptr %2, align 4
  %14 = icmp eq i32 %13, 18
  br i1 %14, label %15, label %27

15:                                               ; preds = %11
  %16 = call i32 (ptr, ...) @__isoc23_scanf(ptr noundef @.str.2, ptr noundef %2)
  %17 = load i32, ptr %2, align 4
  %18 = icmp eq i32 %17, 19
  br i1 %18, label %19, label %26

19:                                               ; preds = %15
  %20 = call i32 (ptr, ...) @__isoc23_scanf(ptr noundef @.str.2, ptr noundef %2)
  %21 = load i32, ptr %2, align 4
  %22 = icmp eq i32 %21, 20
  br i1 %22, label %23, label %25

23:                                               ; preds = %19
  call void @func_a()
  %24 = call i32 (ptr, ...) @printf(ptr noundef @.str.3)
  store i32 0, ptr %1, align 4
  br label %36

25:                                               ; preds = %19
  br label %26

26:                                               ; preds = %25, %15
  br label %27

27:                                               ; preds = %26, %11
  br label %28

28:                                               ; preds = %27, %7
  br label %29

29:                                               ; preds = %28, %0
  call void @func_b()
  %30 = call i64 (i64, ...) @syscall(i64 noundef 186) #3
  %31 = trunc i64 %30 to i32
  store i32 %31, ptr %3, align 4
  %32 = call i32 @getpid() #3
  %33 = load i32, ptr %3, align 4
  %34 = call i64 (i64, ...) @syscall(i64 noundef 234, i32 noundef %32, i32 noundef %33, i32 noundef 1) #3
  %35 = call i32 (ptr, ...) @printf(ptr noundef @.str.4)
  call void @asmlike()
  store i32 1, ptr %1, align 4
  br label %36

36:                                               ; preds = %29, %23
  %37 = load i32, ptr %1, align 4
  ret i32 %37
}

declare i32 @__isoc23_scanf(ptr noundef, ...) #1

; Function Attrs: nounwind
declare i64 @syscall(i64 noundef, ...) #2

; Function Attrs: nounwind
declare i32 @getpid() #2

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 19.1.7"}
!6 = !{i64 322}
