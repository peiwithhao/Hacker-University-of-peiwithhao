#ifndef __FINDCALLINST_H
#define __FINDCALLINST_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/IR/Analysis.h>
#include <vector>

/* 提高编译速度 */
namespace llvm{
    class CallInst;
    class Function;
    class Module;
    class raw_ostream;
}// namespace llvm

/* 分析pass的类 */
class FindFCall : public llvm::AnalysisInfoMixin<FindFCall>{
public:
    using Result = std::vector<llvm::CallInst *>;
    Result run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    //    Result run(llvm::Function &F);
private:
    friend struct llvm::AnalysisInfoMixin<FindFCall>;
    static llvm::AnalysisKey Key;
};

/* 输出Pass的类 */
class FindFCallPrinter : public llvm::PassInfoMixin<FindFCallPrinter>{
public:
    explicit FindFCallPrinter(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    //llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};


/* 模块级别 */
class CallOrder : public llvm::AnalysisInfoMixin<CallOrder>{
public:
    using Result = std::vector<llvm::Function *>;
    Result run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);

private:
    friend struct llvm::AnalysisInfoMixin<CallOrder>;
    static llvm::AnalysisKey Key;
};


/* 输出Pass的类 */
class CallOrderPrinter : public llvm::PassInfoMixin<CallOrderPrinter>{
public:
    explicit CallOrderPrinter(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};


/* 深度遍历加上参数解析 
class DFSArgsParser : public llvm::AnalysisInfoMixin<DFSArgsParser>{
public:
    using Result = std::vector<llvm::Function *>;
    Result run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);

private:
    friend struct llvm::AnalysisInfoMixin<CallOrder>;
    static llvm::AnalysisKey Key;
};
*/


/* 输出Pass的类 */
class DFSArgsParserPrinter : public llvm::PassInfoMixin<DFSArgsParserPrinter>{
public:
    explicit DFSArgsParserPrinter(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};



#endif
