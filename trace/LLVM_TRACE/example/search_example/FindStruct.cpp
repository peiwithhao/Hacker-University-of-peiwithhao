#include "include/FindStruct.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/InstIterator.h"

#include "llvm/Passes/PassBuilder.h"
#include <llvm/IR/PassManager.h>
#include <llvm/Passes/PassPlugin.h>
#include <string>

using namespace llvm;


static void printStructTypes(raw_ostream &OS, Module &M){
    OS << "ModuleName:" << M.getName() << "\n";

    OS << "ID:" << M.getModuleIdentifier() << "\n";

    OS << "InstructionCount:" << M.getInstructionCount() << "\n";

    OS << "Source File Name:" << M.getSourceFileName() << "\n";

    OS <<"VariablesType    VarialblesName\n";
    for(GlobalVariable &var : M.globals()){
        OS << "\t\t" << *var.getType() <<  "\t\t" << var.getName() << "\n";
    }

    /* 获取数据结构体 */
    for(const auto &T : M.getIdentifiedStructTypes()){
        OS <<"======================\n";
        OS << "Structs:" << T->getName() << "\n";
        for(Type *ElementType : T->elements()){
            OS << "Field Type" << *ElementType << "\n";
        }
    }

    for(auto &F : M.getFunctionList()){
        OS << "=========Instructions===========\n";
        for(llvm::Instruction &Inst : instructions(F)){
            if(auto *Call = dyn_cast<CallInst>(&Inst)){
                Function *Callee = Call->getCalledFunction();
                OS << "Found Caller:" << F.getName() << " calls " << Callee->getName() << "\n";
            }else{
                OS << "Regular Instruction:" << Inst << "\n";
            }
        }
    }
}

static constexpr char PassArg[] = "find-struct";
static constexpr char PassName[] = "Found Struct Type";
static constexpr char PluginName[] = "FindStruct";

PreservedAnalyses FindStructPrinter::run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM){
    //auto &Struct_vector = MAM.getResult<FindStruct>(M);
    printStructTypes(OS, M);
    return PreservedAnalyses::all();
}

PassPluginLibraryInfo getFindStructPluginInfo(){
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", PassArg);
                    if(!Name.compare(PrinterPassElement)){
                        MPM.addPass(FindStructPrinter(llvm::outs()));
                        return true;
                    }
                    return false;
                });
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK :: llvm :: PassPluginLibraryInfo llvmGetPassPluginInfo(){
    return getFindStructPluginInfo();
}
