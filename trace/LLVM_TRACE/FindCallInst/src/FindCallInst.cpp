//#include "./include/FindCallInst.h"
#include "FindCallInst.h"
#include <llvm/IR/Analysis.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/FormatVariadic.h>


using namespace llvm;

FindFCall::Result FindFCall::run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM){
    Result CallInstSet;
    for(llvm::Instruction &Inst: instructions(F)){
        if(auto *FCallInst = dyn_cast<CallInst>(&Inst)){
            CallInstSet.push_back(FCallInst);
        }
    }
    return CallInstSet;

}

static void printFCallInstructions(raw_ostream &OS, Function &Func, const FindFCall::Result &CallInstSet){
    if(CallInstSet.empty()){
        return;
    }
    OS << "FuncName:" << Func.getName() << "\n";
    for(CallInst *Fcall : CallInstSet){
        if(llvm::Function* calledfunc = Fcall->getCalledFunction()){
            OS << "\tDirect call: " << calledfunc->getName()<< "\n"; 
        }else{
            OS << "\tIndirect call" << "\n";
        }
        //OS << "callInst:" << Fcall->getNumOperands() << "\n";
        for(auto it = Fcall->arg_begin(); it != Fcall->arg_end(); ++it){
            Value *arg = *it;
            /*
            if (arg->hasName()) {
                OS << "  Arg Name: " << arg->getName() << "\n";
            } else {
                OS << "  Arg: ";
                arg->print(OS);
                OS << "\n";
            }
        */
            //OS << arg->getName() << "\n";
            // 打印常量值
            // 整数参数
            if (auto *constInt = dyn_cast<ConstantInt>(arg)) {
                OS << "\t\tInteger: " << constInt->getValue() << "\n";
            }
            // 浮点数参数
            else if (auto *constFP = dyn_cast<ConstantFP>(arg)) {
                OS << "\t\tFloat: ";
                constFP->getValueAPF().print(OS);
                OS << "\n";
            }
            // 字符串常量
            else if (auto *constStr = dyn_cast<ConstantDataArray>(arg)) {
                OS << "\t\tString: \"" << constStr->getAsString().str() << "\"\n";
            }
            // 可能的全局字符串
            else if (auto *globalVar = dyn_cast<GlobalVariable>(arg)) {
                if (globalVar->hasInitializer()) {
                    if (auto *constStr = dyn_cast<ConstantDataArray>(globalVar->getInitializer())) {
                        OS << "\t\tGlobal String: \"" << constStr->getAsString().str() << "\"\n";
                        continue;
                    }
                }
                OS << "\t\tGlobal Variable: " << globalVar->getName() << "\n";
            }
            // 普通参数
            else {
                OS << "\t\tValue (IR): ";
                arg->print(OS);
                OS << "\n";
            }

        }
    }
}



PreservedAnalyses FindFCallPrinter::run(llvm::Function &Func, llvm::FunctionAnalysisManager &FAM){
    auto &CallInstSet = FAM.getResult<FindFCall>(Func);
    printFCallInstructions(OS, Func, CallInstSet);
    return PreservedAnalyses::all();
}

static constexpr char PluginName[] = "FindFCall";
static constexpr char PassArg[] = "find-fcall";

llvm::AnalysisKey FindFCall::Key;
PassPluginLibraryInfo getFindFCallPluginInfo(){
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            PB.registerAnalysisRegistrationCallback(
                [](FunctionAnalysisManager &FAM){
                    FAM.registerPass([&]{return FindFCall();});
                });
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", PassArg);
                    if(!Name.compare(PrinterPassElement)){
                        FPM.addPass(FindFCallPrinter(llvm::outs()));
                        return true;
                    }
                    return false;
                });
        }
    };
}

extern "C" LLVM_ATTRIBUTE_WEAK :: llvm :: PassPluginLibraryInfo llvmGetPassPluginInfo(){
    return getFindFCallPluginInfo();
}
