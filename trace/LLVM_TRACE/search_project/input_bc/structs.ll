; ModuleID = 'input_bc/structs.bc'
source_filename = "input_bc/structs.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

%struct.tmp_a = type { i64, i64 }
%struct.tmp_x_a = type { ptr, i64 }
%struct.tmp_b = type { [16 x i8], i64 }
%struct.tmp_c = type { i64, i64 }

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local void @fun_a() #0 {
  %1 = alloca %struct.tmp_a, align 8
  %2 = alloca %struct.tmp_x_a, align 8
  %3 = getelementptr inbounds %struct.tmp_x_a, ptr %2, i32 0, i32 1
  store i64 11, ptr %3, align 8
  ret void
}

; Function Attrs: noinline nounwind optnone sspstrong uwtable
define dso_local i32 @main() #0 {
  %1 = alloca %struct.tmp_a, align 8
  %2 = alloca %struct.tmp_x_a, align 8
  %3 = alloca %struct.tmp_b, align 8
  %4 = alloca %struct.tmp_c, align 8
  %5 = getelementptr inbounds %struct.tmp_x_a, ptr %2, i32 0, i32 1
  store i64 99, ptr %5, align 8
  ret i32 0
}

attributes #0 = { noinline nounwind optnone sspstrong uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }

!llvm.module.flags = !{!0, !1, !2, !3, !4}
!llvm.ident = !{!5}

!0 = !{i32 1, !"wchar_size", i32 4}
!1 = !{i32 8, !"PIC Level", i32 2}
!2 = !{i32 7, !"PIE Level", i32 2}
!3 = !{i32 7, !"uwtable", i32 2}
!4 = !{i32 7, !"frame-pointer", i32 2}
!5 = !{!"clang version 18.1.8"}
