; ModuleID = 'many_blocks.c'
source_filename = "many_blocks.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [22 x i8] c"you are a little hog\0A\00", align 1
@.str.1 = private unnamed_addr constant [22 x i8] c"you are a middle hog\0A\00", align 1
@.str.2 = private unnamed_addr constant [19 x i8] c"you are a big hog\0A\00", align 1
@.str.3 = private unnamed_addr constant [23 x i8] c"you are a little coke\0A\00", align 1
@.str.4 = private unnamed_addr constant [20 x i8] c"you are a big coke\0A\00", align 1
@.str.5 = private unnamed_addr constant [12 x i8] c"/dev/random\00", align 1
@.str.6 = private unnamed_addr constant [5 x i8] c"read\00", align 1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @filter_3(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  %4 = load i32, ptr %2, align 4
  %5 = srem i32 %4, 3
  store i32 %5, ptr %3, align 4
  %6 = load i32, ptr %3, align 4
  switch i32 %6, label %13 [
    i32 0, label %7
    i32 1, label %9
    i32 2, label %11
  ]

7:                                                ; preds = %1
  %8 = call i32 (ptr, ...) @printf(ptr noundef @.str)
  br label %14

9:                                                ; preds = %1
  %10 = call i32 (ptr, ...) @printf(ptr noundef @.str.1)
  br label %14

11:                                               ; preds = %1
  %12 = call i32 (ptr, ...) @printf(ptr noundef @.str.2)
  br label %14

13:                                               ; preds = %1
  br label %14

14:                                               ; preds = %13, %11, %9, %7
  ret void
}

declare i32 @printf(ptr noundef, ...) #1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @filter_2(i32 noundef %0) #0 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  store i32 %0, ptr %2, align 4
  %4 = load i32, ptr %2, align 4
  %5 = srem i32 %4, 7
  store i32 %5, ptr %3, align 4
  %6 = load i32, ptr %3, align 4
  switch i32 %6, label %11 [
    i32 0, label %7
    i32 1, label %9
  ]

7:                                                ; preds = %1
  %8 = call i32 (ptr, ...) @printf(ptr noundef @.str.3)
  br label %12

9:                                                ; preds = %1
  %10 = call i32 (ptr, ...) @printf(ptr noundef @.str.4)
  br label %12

11:                                               ; preds = %1
  br label %12

12:                                               ; preds = %11, %9, %7
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @main() #0 {
  %1 = alloca i32, align 4
  %2 = alloca i32, align 4
  %3 = alloca [16 x i8], align 16
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  %6 = call i32 (ptr, i32, ...) @open(ptr noundef @.str.5, i32 noundef 0)
  store i32 %6, ptr %2, align 4
  %7 = load i32, ptr %2, align 4
  %8 = getelementptr inbounds [16 x i8], ptr %3, i64 0, i64 0
  %9 = call i64 @read(i32 noundef %7, ptr noundef %8, i64 noundef 16)
  %10 = trunc i64 %9 to i32
  store i32 %10, ptr %4, align 4
  %11 = load i32, ptr %4, align 4
  %12 = icmp slt i32 %11, 0
  br i1 %12, label %13, label %14

13:                                               ; preds = %0
  call void @perror(ptr noundef @.str.6) #4
  store i32 1, ptr %1, align 4
  br label %19

14:                                               ; preds = %0
  %15 = getelementptr inbounds [16 x i8], ptr %3, i64 0, i64 0
  %16 = call i32 @atoi(ptr noundef %15) #5
  store i32 %16, ptr %5, align 4
  %17 = load i32, ptr %5, align 4
  call void @filter_3(i32 noundef %17)
  %18 = load i32, ptr %5, align 4
  call void @filter_2(i32 noundef %18)
  store i32 0, ptr %1, align 4
  br label %19

19:                                               ; preds = %14, %13
  %20 = load i32, ptr %1, align 4
  ret i32 %20
}

declare i32 @open(ptr noundef, i32 noundef, ...) #1

declare i64 @read(i32 noundef, ptr noundef, i64 noundef) #1

; Function Attrs: cold
declare void @perror(ptr noundef) #2

; Function Attrs: nounwind willreturn memory(read)
declare i32 @atoi(ptr noundef) #3

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { cold "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nounwind willreturn memory(read) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #4 = { cold }
attributes #5 = { nounwind willreturn memory(read) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 18.1.8"}
