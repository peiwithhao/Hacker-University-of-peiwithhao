#include "ctlFinder.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/IR/DerivedUser.h"
#include "llvm/IR/Operator.h"
using namespace llvm;

void inst_addr_printer(Instruction &Inst){
    if(const DebugLoc &debugLoc  = Inst.getDebugLoc()){
        unsigned line = debugLoc.getLine();
        unsigned col = debugLoc.getCol();
        StringRef dir = debugLoc->getDirectory();
        StringRef filename = debugLoc->getFilename();
        errs() << "\t[*]Instruction at \033[35m" << dir << "/" << filename << ":" << line << ":" << col << "\033[0m\n";
    }else{
        errs() << "\tNo debug Info Found...\n";

    }
}

void ctlFinder::do_ctl_finder(GlobalVariable &GV, ctlFinder::Result &result){
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
                    if(s_name.find("ctl_table") != std::string::npos){
                    // if(1){
                        ctl_table_flag = true;
                        // errs() << GV.getName() << "\n";
                        result.push_back(&GV);
                        break;
                    }
                }
            }
        }
    }
}

void ctlFinder::do_ctl_checker(Result &result){
    for(auto it : result){
        errs() << "[+]" << it->getName() << "\n";
        for(User * user : it->users()){
            if(Instruction *inst = dyn_cast<Instruction>(user)){
                inst_addr_printer(*inst);
                errs() << "\t\t";
                if(CallBase *cb = dyn_cast<CallBase>(user)){
                    errs() << "call base\n";
                }else if(CmpInst *ci = dyn_cast<CmpInst>(user)){
                    errs() << "CmpInst\n";
                }else if(StoreInst *si = dyn_cast<StoreInst>(user)){
                    errs() << "StoreInst\n";
                }else if(GetElementPtrInst *gepi = dyn_cast<GetElementPtrInst>(user)){
                    errs() << "GetElementPtrInst\n";
                }else if(PHINode *ph = dyn_cast<PHINode>(user)){
                    errs() << "PHINode\n";
                }else{
                    errs() << "something else: ";
                    user->print(errs());
                    errs() << "\n";
                }
            }else if(Constant *constant = dyn_cast<Constant>(user)){
                do_constant_parser(*constant);
            }else if(DerivedUser *du = dyn_cast<DerivedUser>(user)){
                errs() << "\t[D]";
                du->print(errs());
                errs() << "\n";
            }else if(Operator *op = dyn_cast<Operator>(user)) {
                errs() << "\t[O]";
                op->print(errs());
                errs() << "\n";
            }else {
                errs() << "\t[?]";
                user->print(errs());
                errs() << "\n";
            }
        }
    }
}

void ctlFinder::do_constant_parser(Constant &constant){
    if(ConstantStruct *cs = dyn_cast<ConstantStruct>(&constant)){
        for(User *user : cs->users()){
            if(ConstantArray *ca = dyn_cast<ConstantArray>(user)){
                for(User *array_user : ca->users()){
                    errs() << "\t[C]Used in initialstruct: " <<  array_user->getName() << "\n";
                    // if(GlobalVariable *GV = dyn_cast<GlobalVariable>(ca)){
                    //     errs() << GV->getName() << "\n";
                    // }
                }
            }
        }
    }
}



ctlFinder::Result ctlFinder::run(Module &M, ModuleAnalysisManager &MAM){
    Result result;
    //Step 1: Find the ctl_table
    for(GlobalVariable &GV : M.globals()){
        // errs() << GV.getName() << "\n";
        do_ctl_finder(GV, result);
    }
    //Step 2: Check the ctl_table
    do_ctl_checker(result);
    return result;
}

PreservedAnalyses ctlPrinter::run(Module &M, ModuleAnalysisManager &MAM){
    ctlFinder::Result result = MAM.getResult<ctlFinder>(M);
    return PreservedAnalyses::all();
}



AnalysisKey ctlFinder::Key;

PassPluginLibraryInfo getctlPluginInfo(){
    return {
        LLVM_PLUGIN_API_VERSION,"ctlFinderPlugin",LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                   [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return ctlFinder();});
                }
            );

            PB.registerPipelineParsingCallback(
            [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    if (Name == "find-her"){
                        MPM.addPass(ctlPrinter());

                        return true;
                    }
                    return false; });
        }

    };
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getctlPluginInfo();
}


