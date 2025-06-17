#include "ktfinder.h"
#include "utils.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;



KTFinder::Result KTFinder::run(Module &M, ModuleAnalysisManager &MAM){
    Result result;
    StringRef targetFuncName = "kthread_create_on_node";
    Function *func = M.getFunction(targetFuncName);
    if(func)
        do_CallerTrace(*func);
        // FunctionCallerTraverse(*func);
    return result;
}


PreservedAnalyses KTPrinter::run(Module &M, ModuleAnalysisManager &MAM){
    auto &result = MAM.getResult<KTFinder>(M);
    return PreservedAnalyses::all(); }


AnalysisKey KTFinder::Key;

PassPluginLibraryInfo getKthreadFinderPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"KthreadFinderPlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return KTFinder();});
                }
            );

            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(KTPrinter());
                        return true;
                    }
                    return false; });
        }

    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getKthreadFinderPluginInfo();
}


