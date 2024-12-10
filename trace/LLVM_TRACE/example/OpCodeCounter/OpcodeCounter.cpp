#include "include/OpcodeCounter.h"

#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include <llvm/IR/PassManager.h>

using namespace llvm;

/* 传递第二个参数为头文件定义的stringmap */
static void printOpcodeCounterResult(llvm::raw_ostream &, const ResultOpcodeCounter &OC);

/* 声明一个Key */
llvm::AnalysisKey OpcodeCounter::Key;

OpcodeCounter::Result OpcodeCounter::generateOpcodeMap(llvm::Function &F){
    /* 声明一个OpcodeCounter实例 */
    OpcodeCounter::Result OpcodeMap;
    for(auto &BB : F){
        for(auto &Inst : BB){
            StringRef Name = Inst.getOpcodeName();
            /* 这里说明没找到同类型的key */
            if(OpcodeMap.find(Name) == OpcodeMap.end()){
                OpcodeMap[Inst.getOpcodeName()] = 1;
            }else{
                OpcodeMap[Inst.getOpcodeName()]++;
            }
        }
    }
    return OpcodeMap;
}

OpcodeCounter::Result OpcodeCounter::run(llvm::Function &F, llvm::FunctionAnalysisManager &){
    return generateOpcodeMap(F);
}


static void printOpcodeCounterResult(raw_ostream &OutS, const ResultOpcodeCounter &OpcodeMap){
    OutS << "======================================" << "\n";
    OutS << "OpcodeCounter results\n";
    const char *str1 = "OPCODE";
    const char *str2 = "#TIMES USED";
    OutS << format("%-20s %-10s\n", str1, str2);
    OutS << "--------------------------------------" << "\n";
    for(auto &Inst : OpcodeMap){
        /* 打印键值对 */
        OutS << format("%-20s %-10lu\n", Inst.first().str().c_str(), Inst.second);
    }
    OutS << "--------------------------------------" << "\n\n";
}

PreservedAnalyses OpcodeCounterPrinter::run(Function &F, FunctionAnalysisManager &FAM){
    auto &OpcodeMap = FAM.getResult<OpcodeCounter>(F);
    OS << "Printing analysis 'OpcodeCounter Pass' for function '" << F.getName() << "':\n";
    printOpcodeCounterResult(OS, OpcodeMap);
    return PreservedAnalyses::all();
}

/* PM的注册 */
llvm::PassPluginLibraryInfo getOpcodeCounterPluginInfo() {
    return {
        LLVM_PLUGIN_API_VERSION, "OpcodeCounter", LLVM_VERSION_STRING,
            [](PassBuilder &PB){
            /* 管道解析期间 */
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>){
                    if(Name == "print<opcode-counter>"){
                        FPM.addPass(OpcodeCounterPrinter(llvm::errs()));
                        return true;
                    }
                    return false;
                }
            );
            /* 向量化开始阶段,Pass优化阶段 */
            PB.registerVectorizerStartEPCallback(
                [](llvm::FunctionPassManager &PM, llvm::OptimizationLevel level){
                    PM.addPass(OpcodeCounterPrinter(llvm::errs()));
                }
            );
            /* 分析Pass注册阶段 */
            PB.registerAnalysisRegistrationCallback(
                [](FunctionAnalysisManager &FAM){
                    FAM.registerPass([&] {return OpcodeCounter();});
                }
            );
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK :: llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo(){
    return getOpcodeCounterPluginInfo();
}


