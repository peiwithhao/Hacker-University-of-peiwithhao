#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"

using namespace llvm;

void FunctionCallerTraverse(llvm::Function &func);
void source_trace_back(llvm::User *user, unsigned int stack_level);
void do_CallerTrace(llvm::Function &func);

