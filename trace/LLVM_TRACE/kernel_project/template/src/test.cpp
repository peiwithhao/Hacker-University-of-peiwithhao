#include "test.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;


TemplateAnalyzer::Result TemplateAnalyzer::run(Module &M, ModuleAnalysisManager &MAM){
    Result result;
    for(GlobalVariable &GV : M.globals()){
        result.push_back(&GV);
    }
    return result;
}


PreservedAnalyses TemplateTransformer::run(Module &M, ModuleAnalysisManager &MAM){
    auto &result = MAM.getResult<TemplateAnalyzer>(M);
    errs() << "Module Name: " << M.getName() << "\n";
    return PreservedAnalyses::all();
}


AnalysisKey TemplateAnalyzer::Key;

PassPluginLibraryInfo getGlobalVarPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"GlobalVariablePlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return TemplateAnalyzer();});
                }
            );

            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(TemplateTransformer());
                        return true;
                    }
                    return false; });
        }

    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getGlobalVarPluginInfo();
}


