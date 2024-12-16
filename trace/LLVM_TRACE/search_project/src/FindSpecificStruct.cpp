#include "../include/FindSpecificStruct.h"

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

static auto findStruct(llvm::raw_ostream &OS, llvm::Module &M){
    std::vector<StructType *> Result;
    /* 获取数据结构体 */
    for(const auto &T : M.getIdentifiedStructTypes()){
        // OS << "Structs:" << T->getName() << "\n";
        // for(Type *ElementType : T->elements()){
        //     OS << "Field Type" << *ElementType << "\n";
        // }
        auto ElementTypes = T->elements();
        if(!ElementTypes.empty()){
            if(isa<PointerType>(ElementTypes[0])){
                Result.push_back(T);
                break;
            } 
        }
    }
    return Result;

}

static auto findUser(llvm::raw_ostream &OS, std::vector<StructType *> array, llvm::Module &M){

    for(StructType *st : array){
        OS << "Struct Specific Name : " << st->getName() << "\n";
        for(auto &F : M.getFunctionList()){
            for(Instruction &Inst : instructions(F)){
                OS << "Inst: " << Inst.getOpcodeName() << "\n";
                for(llvm::Value *Op : Inst.operands()){
                    if(PointerType *pt = dyn_cast<PointerType>(Op->getType())){
                        if(Op->getType() == st){
                            OS << "Function " << F.getName() << "use Instuction" << Inst.getOpcodeName() << "use struct " << st->getName() << "via pointer\n";
                        }
                    }else if(Op->getType() == st){
                            OS << "Function " << F.getName() << "use Instuction" << Inst.getOpcodeName() << "use struct " << st->getName() << "\n";
                    }
                }
            }
        }
    }

}


PreservedAnalyses FindSpecificStruct::run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM){
    auto structs_vector =  findStruct(OS, M);
    findUser(OS, structs_vector, M);

    return PreservedAnalyses::all();
}

static constexpr char PassArg[] = "find-specific-struct";
static constexpr char PassName[] = "Found Specific Struct Type";
static constexpr char PluginName[] = "FindSpecificStruct";


PassPluginLibraryInfo getFindSpecificStructPluginInfo(){
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", PassArg);
                    if(!Name.compare(PrinterPassElement)){
                        MPM.addPass(FindSpecificStruct(llvm::outs()));
                        return true;
                    }
                    return false;
                });
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK :: llvm :: PassPluginLibraryInfo llvmGetPassPluginInfo(){
    return getFindSpecificStructPluginInfo();
}





