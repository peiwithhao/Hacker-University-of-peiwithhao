#include "ctxFinder.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;

void ctxFinder::do_ctx_finder(GlobalVariable &GV, ctxFinder::Result &result){
    //ctl table array
    bool ctl_table_flag = false;
    if(GV.getValueType()->isArrayTy()){
        Type *t = GV.getValueType()->getArrayElementType();
        //ctl table
        if(t->isStructTy()){
            // get the initial value
            if(GV.hasInitializer()){
                Constant *GVInit = GV.getInitializer();
                ArrayType *St =  dyn_cast<ArrayType>(GVInit->getType());
                if(!St){
                    errs() << "Something Wrong happend";
                    return;
                }
                if(!St->getNumElements()){
                    errs() << "There is no Elements\n";
                    return;
                }
                ConstantArray *ca = dyn_cast<ConstantArray>(GVInit);
                if(!ca){
                    // errs() << "Asshole\n";
                    return;
                }
                for (unsigned i = 0; i < ca->getNumOperands(); ++i) {
                    ConstantStruct *cs = dyn_cast<ConstantStruct>(ca->getOperand(i));
                    if(!cs) continue;
                    StringRef s_name = cs->getType()->getStructName();
                    // for (unsigned struct_index = 0; struct_index < cs->getNumOperands(); ++struct_index){
                    //     Value *test = cs->getOperand(struct_index);
                    //     Type *StructType = test->getType();
                    //     StructType->print(errs());
                    //     errs() << "\n";
                    // }

                    // StringRef struct_name = element->getType()->getStructName();
                    // errs() << "StringRef: " << struct_name << "\n";
                    if(s_name.find("ctl_table") != std::string::npos){
                        ctl_table_flag = true;
                        errs() << GV.getName() << "\n";
                        break;
                        // result.push_back(&GV);
                    }

                    // Element->print(errs());
                    // errs() << "\n";
                }
                // GVInit->print(errs());
                // errs() << "\n";
                // getchar();
            }
            // t->print(errs());
        }
        // errs() << "\n";
        // t->print(errs());
        // for(auto it = result.begin(); it != result.end(); ++it){
        //     if(t == *it){
        //         return;
        //     }
        // }
        // result.push_back(t);
    }

}

ctxFinder::Result ctxFinder::run(Module &M, ModuleAnalysisManager &MAM){
    Result result;
    for(GlobalVariable &GV : M.globals()){
        //means just str constant
        if(!GV.getName().find(".str", 0)){
            continue;
        }
        // errs() << GV.getName() << "\n";
        do_ctx_finder(GV, result);
    }
    // errs() << "Types" << "\n";
    // for(auto it = result.begin(); it != result.end(); ++it){
    //     (*it)->print(errs());
    //     errs() << "\n";
    // }
    return result;
}

PreservedAnalyses ctxPrinter::run(Module &M, ModuleAnalysisManager &MAM){
    ctxFinder::Result result = MAM.getResult<ctxFinder>(M);
    return PreservedAnalyses::all();
}



AnalysisKey ctxFinder::Key;

PassPluginLibraryInfo getCtxPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"ctxFinderPlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return ctxFinder();});
                }
            );

            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(ctxPrinter());

                        return true;
                    }
                    return false; });
        }

    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getCtxPluginInfo();
}


