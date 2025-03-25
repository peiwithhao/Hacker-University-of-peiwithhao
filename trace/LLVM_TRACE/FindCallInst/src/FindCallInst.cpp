//#include "./include/FindCallInst.h"
#include "FindCallInst.h"
#include <llvm/IR/Analysis.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Instruction.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <llvm/Support/FormatVariadic.h>
#include <llvm/IR/Module.h>
#include <vector>

using llvm::AnalysisKey;
using llvm::Function;

using namespace llvm;
/* 查找所有代码块的内容，不按顺序 */
FindFCall::Result FindFCall::run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM){
    Result CallInstSet;
    for(llvm::Instruction &Inst: instructions(F)){
        if(auto *FCallInst = dyn_cast<CallInst>(&Inst)){
            CallInstSet.push_back(FCallInst);
        }
    }
    return CallInstSet;

}


static void dfs(Function *func, std::vector<Function *> &callStack, std::vector<Function *> &callOrder){
    if (!func) {
        return;  // 防止重复遍历
    }
    /* 标识为已经访问 */
    callStack.push_back(func);
    /* 将函数添加至顺序表 */
    callOrder.push_back(func);

    for(llvm::Instruction &Inst: instructions(func)){
        if(auto *FCallInst = dyn_cast<CallInst>(&Inst)){
            if (std::find(callStack.begin(), callStack.end(), FCallInst->getCalledFunction()) != callStack.end()) {
                errs() << "\t\t Detected recursive call:" << FCallInst->getCalledFunction()->getName() << "\n";
                continue; // 跳过递归调用，避免死循环
            }
            dfs(FCallInst->getCalledFunction(), callStack, callOrder);
        }
    }
    callStack.pop_back();
}

/* DFS遍历函数获取call顺序*/
CallOrder::Result CallOrder::run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM){
    /* 存放调用栈 */
    std::vector<Function *> callStack;
    /* 存放遍历函数 */
    Result callOrder;

    Function *mainFunc = M.getFunction("main");
    if(!mainFunc){
        errs() << "Error! There is no main func..\n";
    }
    dfs(mainFunc, callStack, callOrder);
    return callOrder;
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


PreservedAnalyses CallOrderPrinter::run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM){
    //auto &CallOrder = MAM.getResult<CallOrder>(M);
    const std::vector<llvm::Function *> &callOrder = MAM.getResult<CallOrder>(M);
    for(auto *func : callOrder){
        OS << func->getName() << ":" << func->arg_size() << "\n";
    }
    return PreservedAnalyses::all();
}



static void SimplifyInstructions(raw_ostream &OS, Function &Func){

    for(llvm::Instruction &Inst: instructions(Func)){
        if(auto *FCallInst = dyn_cast<CallInst>(&Inst)){
            if(llvm::Function* calledfunc = FCallInst->getCalledFunction()){
                OS << calledfunc->getName()<< "("; 
            }else{
                continue;
            }
            //OS << "callInst:" << Fcall->getNumOperands() << "\n";
            for(auto it = FCallInst->arg_begin(); it != FCallInst->arg_end(); ++it){
                Value *arg = *it;
                // 打印常量值
                // 整数参数
                if (auto *constInt = dyn_cast<ConstantInt>(arg)) {
                    OS << constInt->getValue() << ",";
                }
                // 浮点数参数
                else if (auto *constFP = dyn_cast<ConstantFP>(arg)) {
                    constFP->getValueAPF().print(OS);
                    OS << ",";
                }
                // 字符串常量
                else if (auto *constStr = dyn_cast<ConstantDataArray>(arg)) {
                    OS << "\"" << constStr->getAsString().str() << "\",";
                }
                // 可能的全局字符串
                else if (auto *globalVar = dyn_cast<GlobalVariable>(arg)) {
                    if (globalVar->hasInitializer()) {
                        if (auto *constStr = dyn_cast<ConstantDataArray>(globalVar->getInitializer())) {
                            OS << "\"" <<constStr->getAsString().str() << "\",";
                            continue;
                        }
                    }
                    OS << globalVar->getName() << ",";
                }
                // 普通参数
                else {
                    arg->print(OS);
                    OS << ",";
                }
            }
            OS << ");\n";
        }
    }
}



PreservedAnalyses DFSArgsParserPrinter::run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM){
    //auto &CallOrder = MAM.getResult<CallOrder>(M);
    const std::vector<llvm::Function *> &callOrder = MAM.getResult<CallOrder>(M);
    for(auto *func : callOrder){
        SimplifyInstructions(OS, *func);
    }
    return PreservedAnalyses::all();
}




static constexpr char PluginName[] = "FindFCall";
static constexpr char Arg_Parser_CMD[] = "arg_parser";
static constexpr char DFS_Parser_CMD[] = "dfs_parser";
static constexpr char DFS_ARGS_Parser_CMD[] = "dfs_args_parser";

AnalysisKey FindFCall::Key;
AnalysisKey CallOrder::Key;

PassPluginLibraryInfo getFindFCallPluginInfo(){
    return {LLVM_PLUGIN_API_VERSION, PluginName, LLVM_VERSION_STRING,
        [](PassBuilder &PB){
            /* 注册函数级分析Pass */
            PB.registerAnalysisRegistrationCallback(
                [](FunctionAnalysisManager &FAM){
                    FAM.registerPass([&]{return FindFCall();});
                });
            /* 注册模块级分析Pass: 分析DFS调用 */
            PB.registerAnalysisRegistrationCallback(
                [](ModuleAnalysisManager &MAM){
                    MAM.registerPass([&]{return CallOrder();});
                });
                
            /* 注册函数及Pass打印: 打印call指令参数 */
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, FunctionPassManager &FPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", Arg_Parser_CMD);
                    if(!Name.compare(PrinterPassElement)){
                        FPM.addPass(FindFCallPrinter(llvm::outs()));
                        return true;
                    }
                    return false;
                });
            /* 注册函数及Pass打印: 打印call指令参数 */
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", DFS_Parser_CMD);
                    if(!Name.compare(PrinterPassElement)){
                        MPM.addPass(CallOrderPrinter(llvm::outs()));
                        return true;
                    }
                    return false;
                });
            PB.registerPipelineParsingCallback(
                [&](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>){
                    std::string PrinterPassElement = formatv("print<{0}>", DFS_ARGS_Parser_CMD);
                    if(!Name.compare(PrinterPassElement)){
                        MPM.addPass(DFSArgsParserPrinter(llvm::outs()));
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
