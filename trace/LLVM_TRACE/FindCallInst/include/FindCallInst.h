#ifndef __FINDCALLINST_H
#define __FINDCALLINST_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
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
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};

#endif
