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

/* 寻找特定结构的数据结构体声明 */
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
                continue;
            } 
        }
    }
    return Result;
}

static auto findUser(llvm::raw_ostream &OS, std::vector<StructType *> array, llvm::Module &M){

    /* 遍历特殊结构体 */
    for(StructType *st : array){
        OS << "\033[33mStruct Specific Name : " << st->getName() << "\033[0m\n";
        /* 遍历每个函数 */
        for(auto &F : M.getFunctionList()){
            OS << "\033[31m" <<F.getName() << "\033[0m\n";
            /* 遍历函数指令 */
            for(Instruction &Inst : instructions(F)){
                /* 如果是store指令 */
                if(auto *si = dyn_cast<StoreInst>(&Inst)){
                    Value *Ptr = si->getPointerOperand();
                    /* 判断存储的目的指针若与struct相关 */
                    if(auto *GEP = dyn_cast<GetElementPtrInst>(Ptr)){
                        if(GEP->getSourceElementType() == st){
                            Value *ValueToStore = si->getValueOperand();
                            OS << "\t" << *ValueToStore << " ++++ " << *si->getPointerOperand() << "\n";
                        }
                    }
                /* 如果是call指令 */
                }else if(auto *ci = dyn_cast<CallInst>(&Inst)){
                    Value *CalledValue = ci->getCalledOperand();
                    Value *CallerValue = ci->getCaller();
                    for(int i = 0; i < ci->arg_size(); i++){
                        Value *Ptr = ci->getArgOperand(i);
                        /* 如果发现某个参数为alloca struct */
                        if(auto *ai = dyn_cast<AllocaInst>(Ptr)){
                            if(ai->getAllocatedType() == st){
                                OS << "call" << *ai <<"\n";
                                break;
                            }
                        }
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





