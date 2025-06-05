#include "FGVar.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
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

GlobalVarUserFinder::Result GlobalVarUserFinder::run(Function &F, FunctionAnalysisManager &FAM){
    Result result;
    result.push_back(&F);
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

PreservedAnalyses GlobalVarUserPrinter::run(Function &F, FunctionAnalysisManager &FAM){
    auto &result = FAM.getResult<GlobalVarUserFinder>(F);
    errs() << "Function Name: " << F.getName() << "\n";
    return PreservedAnalyses::all();
}


AnalysisKey GlobalVarFinder::Key;
AnalysisKey GlobalVarUserFinder::Key;

PassPluginLibraryInfo getGlobalVarPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"GlobalVariablePlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return GlobalVarFinder();});
                }
            );

            PB.registerAnalysisRegistrationCallback(
                   [](FunctionAnalysisManager &FAM){
                    FAM.registerPass([&]{return GlobalVarUserFinder();});
                }
            );
            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(GlobalVarPrinter());

                        FunctionPassManager FPM;
                        FPM.addPass(GlobalVarUserPrinter());
                        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));

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


