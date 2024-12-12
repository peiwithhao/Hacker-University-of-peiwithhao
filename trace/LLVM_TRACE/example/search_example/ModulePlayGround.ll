; ModuleID = './ModulePlayGround.c'
source_filename = "./ModulePlayGround.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.st_b = type { ptr, ptr, [32 x i8] }
%struct.st_a = type { i64, ptr, [16 x i8] }

@global_a = dso_local global i64 0, align 8
@global_b = dso_local global i64 0, align 8
@global_c = dso_local global i64 0, align 8
@global_d = dso_local global i64 0, align 8
@global_e = dso_local global i64 0, align 8
@.str = private unnamed_addr constant [11 x i8] c"peiwithhao\00", align 1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @vuln_a() #0 {
  %1 = alloca i32, align 4
  %2 = alloca %struct.st_b, align 8
  store i32 0, ptr %1, align 4
  call void @llvm.memset.p0.i64(ptr align 8 %2, i8 0, i64 48, i1 false)
  %3 = load i32, ptr %1, align 4
  ret i32 %3
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: write)
declare void @llvm.memset.p0.i64(ptr nocapture writeonly, i8, i64, i1 immarg) #1

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @vuln_b(i32 noundef %0, i32 noundef %1) #0 {
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca %struct.st_a, align 8
  store i32 %0, ptr %3, align 4
  store i32 %1, ptr %4, align 4
  store i32 1, ptr %3, align 4
  call void @llvm.memset.p0.i64(ptr align 8 %5, i8 0, i64 32, i1 false)
  %6 = getelementptr inbounds %struct.st_a, ptr %5, i32 0, i32 0
  store i64 14, ptr %6, align 8
  %7 = getelementptr inbounds %struct.st_a, ptr %5, i32 0, i32 2
  %8 = getelementptr inbounds [16 x i8], ptr %7, i64 0, i64 0
  call void @llvm.memcpy.p0.p0.i64(ptr align 8 %8, ptr align 1 @.str, i64 10, i1 false)
  store i32 2, ptr %4, align 4
  %9 = load i32, ptr %3, align 4
  %10 = load i32, ptr %4, align 4
  %11 = add nsw i32 %9, %10
  ret i32 %11
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #2

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @vuln_c(i32 noundef %0, i32 noundef %1, i32 noundef %2) #0 {
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  store i32 %0, ptr %4, align 4
  store i32 %1, ptr %5, align 4
  store i32 %2, ptr %6, align 4
  store i32 1, ptr %4, align 4
  store i32 2, ptr %5, align 4
  store i32 3, ptr %6, align 4
  %7 = load i32, ptr %4, align 4
  %8 = load i32, ptr %5, align 4
  %9 = add nsw i32 %7, %8
  %10 = load i32, ptr %6, align 4
  %11 = add nsw i32 %9, %10
  ret i32 %11
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nounwind willreturn memory(argmem: write) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 18.1.8"}
