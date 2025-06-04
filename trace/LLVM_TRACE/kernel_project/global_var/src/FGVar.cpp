#include "FGVar.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;


GlobalVarFinder::Result GlobalVarFinder::run(Module &M, ModuleAnalysisManager &MAM){
    Result result;
    for(GlobalVariable &GV : M.globals()){
        result.push_back(&GV);
    }
    return result;
}

PreservedAnalyses GlobalVarPrinter::run(Module &M, ModuleAnalysisManager &MAM){
    auto &result = MAM.getResult<GlobalVarFinder>(M);
    errs() << "Module Name: " << M.getName() << "\n";
    for(GlobalVariable *GV : result){
        if(GV->hasName())
            errs() << "\tGlobalVariable: " << GV->getName() << "\n";
        else
            errs() << "\tUnknown Variable\n";
    }
    return PreservedAnalyses::all();
}

AnalysisKey GlobalVarFinder::Key;

PassPluginLibraryInfo getGlobalVarPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"GlobalVariablePlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return GlobalVarFinder();});
                }
            );
            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(GlobalVarPrinter());
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


