#include "include/FindCmpEq.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/ModuleSlotTracker.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/FormatVariadic.h"

#include <string>

using namespace llvm;


FindFCmpEq::Result FindFCmpEq::run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM){
    return run(F);
}

FindFCmpEq::Result FindFCmpEq::run(llvm::Function &F){
    Result Comparisons;
    /* 遍历每个函数的Instrument */
    for(llvm::Instruction &Inst : instructions(F)){
            /* 用来检测是否能安全的转换类型 */
        if(auto *FCmp = dyn_cast<FCmpInst>(&Inst)){
            if(FCmp->isEquality()){
                Comparisons.push_back(FCmp);
            }
        }
    }
    return Comparisons;
}

static void printFCmpEqInstructions(raw_ostream &OS, Function &Func, const FindFCmpEq::Result &FCmpEqInsts){
    OS << "start print\n";
    if(FCmpEqInsts.empty())
        return;
    OS << "(Floating-point equality comparisons in \"" << Func.getName() << "\":\n";
    ModuleSlotTracker Tracker(Func.getParent());
    for(FCmpInst *FCmpEq : FCmpEqInsts){
        FCmpEq->print(OS, Tracker);
        OS << '\n';
    }
}

static constexpr char PassArg[] = "find-fcmp-eq";
static constexpr char PassName[] = "Floating-point equality comparisons locator";
static constexpr char PluginName[] = "FindFCmpEq";



PreservedAnalyses FindFCmpEqPrinter::run(llvm::Function &Func, llvm::FunctionAnalysisManager &FAM){
    /* auto &是别名的意思 */
    auto &Comparisons = FAM.getResult<FindFCmpEq>(Func);
    printFCmpEqInstructions(OS, Func, Comparisons);
    return PreservedAnalyses::all();
}

llvm::AnalysisKey FindFCmpEq::Key;
PassPluginLibraryInfo getFindFCmpEqPluginInfo(){
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                [](FunctionAnalysisManager &FAM){
                    FAM.registerPass([&]{return FindFCmpEq();});
                });
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", PassArg);
                    if(!Name.compare(PrinterPassElement)){
                        FPM.addPass(FindFCmpEqPrinter(llvm::outs()));
                        return true;
                    }
                    return false;
                });
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK :: llvm :: PassPluginLibraryInfo llvmGetPassPluginInfo(){
    return getFindFCmpEqPluginInfo();
}







