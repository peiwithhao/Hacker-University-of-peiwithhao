; ModuleID = './input_bc/structs.c'
source_filename = "./input_bc/structs.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.tmp_a = type { i64, i64 }
%struct.tmp_x_a = type { ptr, i64 }
%struct.tmp_x_b = type { ptr, i64 }
%struct.tmp_b = type { [16 x i8], i64 }
%struct.tmp_c = type { i64, i64 }

@.str = private unnamed_addr constant [4 x i8] c"pwh\00", align 1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @fun_a() #0 {
  %1 = alloca %struct.tmp_a, align 8
  %2 = alloca %struct.tmp_x_a, align 8
  %3 = getelementptr inbounds %struct.tmp_x_a, ptr %2, i32 0, i32 1
  store i64 11, ptr %3, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @fun_b() #0 {
  %1 = alloca ptr, align 8
  %2 = call noalias ptr @malloc(i64 noundef 16) #4
  store ptr %2, ptr %1, align 8
  %3 = load ptr, ptr %1, align 8
  %4 = getelementptr inbounds %struct.tmp_x_a, ptr %3, i32 0, i32 1
  store i64 114514, ptr %4, align 8
  %5 = load ptr, ptr %1, align 8
  call void @free(ptr noundef %5) #5
  ret void
}

; Function Attrs: nounwind allocsize(0)
declare noalias ptr @malloc(i64 noundef) #1

; Function Attrs: nounwind
declare void @free(ptr noundef) #2

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @fun_c(ptr noundef %0, i32 noundef %1, ptr noundef %2) #0 {
  %4 = alloca ptr, align 8
  %5 = alloca i32, align 4
  %6 = alloca ptr, align 8
  %7 = alloca %struct.tmp_x_a, align 8
  %8 = alloca %struct.tmp_x_b, align 8
  store ptr %0, ptr %4, align 8
  store i32 %1, ptr %5, align 4
  store ptr %2, ptr %6, align 8
  %9 = load ptr, ptr %4, align 8
  %10 = getelementptr inbounds %struct.tmp_x_a, ptr %7, i32 0, i32 0
  store ptr %9, ptr %10, align 8
  %11 = load i32, ptr %5, align 4
  %12 = sext i32 %11 to i64
  %13 = getelementptr inbounds %struct.tmp_x_a, ptr %7, i32 0, i32 1
  store i64 %12, ptr %13, align 8
  %14 = load ptr, ptr %6, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %8, ptr align 8 %14, i64 16, i1 false)
  ret void
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @fun_d(ptr noundef %0, ptr noundef %1) #0 {
  %3 = alloca ptr, align 8
  %4 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  store ptr %1, ptr %4, align 8
  %5 = load ptr, ptr %3, align 8
  %6 = getelementptr inbounds %struct.tmp_x_b, ptr %5, i32 0, i32 0
  %7 = load ptr, ptr %6, align 8
  %8 = load ptr, ptr %4, align 8
  call void @llvm.memcpy.p0.p0.i64(ptr align 1 %7, ptr align 1 %8, i64 1, i1 false)
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @main() #0 {
  %1 = alloca %struct.tmp_a, align 8
  %2 = alloca %struct.tmp_x_a, align 8
  %3 = alloca %struct.tmp_b, align 8
  %4 = alloca %struct.tmp_c, align 8
  %5 = alloca %struct.tmp_x_b, align 8
  %6 = alloca i64, align 8
  %7 = getelementptr inbounds %struct.tmp_x_a, ptr %2, i32 0, i32 1
  store i64 99, ptr %7, align 8
  %8 = getelementptr inbounds %struct.tmp_x_b, ptr %5, i32 0, i32 0
  store ptr @.str, ptr %8, align 8
  store i64 999, ptr %6, align 8
  call void @fun_c(ptr noundef %6, i32 noundef 323, ptr noundef %5)
  ret i32 0
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nounwind allocsize(0) "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #2 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nounwind allocsize(0) }
attributes #5 = { nounwind }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 18.1.8"}
