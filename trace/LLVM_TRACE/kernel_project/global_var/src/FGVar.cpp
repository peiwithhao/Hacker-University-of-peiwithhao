#include "FGVar.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
using namespace llvm;


void inst_addr_printer(Instruction &Inst);
void GlobalVarFinder::do_globalvar_finder(GlobalVariable &GV, GlobalVarFinder::Result &result){
    if(GV.hasName()){
        if (GV.getName().find("dirty_ratio")!=std::string::npos || GV.getName().find("dirty_background_ratio") != std::string::npos){
            errs() << "\033\[34;1m[+]\033[0m GlobalVariable:\033[33m " << GV.getName() << "\033[0m\n";
            for(User *U: GV.users()){
                if(Instruction *Inst = dyn_cast<Instruction>(U)){
                    errs() << "\t[+] Used in Instruction: ";
                    inst_addr_printer(*Inst);
                    // errs()<< "\tUsed in Instruction: ";
                    // Inst->print(errs());
                    // errs() << "\n";
                }else if(Constant *Const = dyn_cast<Constant>(U)) {
                    errs() << "\t[+] Used in Constant: ";
                    Const->print(errs());
                    errs() << "\n";
                }else{
                    errs() << "\t[+] Used in: "<< U->getName() << "\n";
                }
            }
        }else{
            return;
        }
    }else
        errs() << "\033\[31;1m[x]\033[0m Unknown Variable\n";
}


GlobalVarFinder::Result GlobalVarFinder::run(Module &M, ModuleAnalysisManager &MAM){
    GlobalVarFinder::Result result;
    for(GlobalVariable &GV : M.globals()){
        do_globalvar_finder(GV, result);
    }
    return result;
}



PreservedAnalyses GlobalVarPrinter::run(Module &M, ModuleAnalysisManager &MAM){
    auto &result = MAM.getResult<GlobalVarFinder>(M);
    // errs() << "Module Name: " << M.getName() << "\n";
    // for(GlobalVariable *GV : result){
    //     if(GV->hasName())
    //         errs() << "\tGlobalVariable: " << GV->getName() << "\n";
    //     else
    //         errs() << "\tUnknown Variable\n";
    // }
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

void inst_addr_printer(Instruction &Inst){
    if(const DebugLoc &debugLoc  = Inst.getDebugLoc()){
        unsigned line = debugLoc.getLine();
        unsigned col = debugLoc.getCol();
        StringRef dir = debugLoc->getDirectory();
        StringRef filename = debugLoc->getFilename();
        if(dir.find("virtio")!=std::string::npos || filename.find("virtio")!=std::string::npos ){
            errs() << "\t[*]Instruction at \033[35m" << dir << "/" << filename << ":" << line << ":" << col << "\033[0m\n";
        }
    }else{
        errs() << "\tNo debug Info Found...\n";

    }
}



