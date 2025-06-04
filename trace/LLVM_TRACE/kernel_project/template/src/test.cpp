#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
using namespace llvm;


void do_something(Function &F){
    errs()<<"hello from: "<< F.getName() << "\n";
}



struct pwh_template : PassInfoMixin<pwh_template>{
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &){
        do_something(F);
        return PreservedAnalyses::all();
    }
    static bool isRequired(){return true; }

};

PassPluginLibraryInfo gettemplatePluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"template",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerPipelineParsingCallback(
            [](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "template"){
                        FPM.addPass(pwh_template());
                        return true;
                    }
                    return false; }
        );
        }

    };
}


extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {

  return gettemplatePluginInfo();
}


