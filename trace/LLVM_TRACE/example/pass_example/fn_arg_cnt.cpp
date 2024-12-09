#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

/* 统计函数和参数 */
namespace{
    void visitor(Function &F) {
        errs() << "Function name: " << F.getName() << "\n";
        errs() << "Number of the arguments: " << F.arg_size() << "\n";
    }

    /* 新PM的实现 */
    struct FnArgCnt : PassInfoMixin<FnArgCnt> {
        PreservedAnalyses run(Function &F, FunctionAnalysisManager &){
            visitor(F);
            return PreservedAnalyses::all();
        }
        static bool isRequired() {return true;}
    };
}//namespace



/* 注册Pass */
//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
llvm::PassPluginLibraryInfo getFnArgCntPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FnArgCnt", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "fnargcnt") {
                    FPM.addPass(FnArgCnt());
                    return true;
                  }
                  return false;
                });
          }};
}

// This is the core interface for pass plugins. It guarantees that 'opt' will
// be able to recognize HelloWorld when added to the pass pipeline on the
// command line, i.e. via '-passes=hello-world'
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getFnArgCntPluginInfo();
}
