#ifndef __FINDCMPEQ_H
#define __FINDCMPEQ_H

#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include <vector>


/* 提高编译速度 */
namespace llvm{

class FCmpInst;
class Function;
class Module;
class raw_ostream;

}// namespace llvm

class FindFCmpEq : public llvm::AnalysisInfoMixin<FindFCmpEq>{
public:
    using Result = std::vector<llvm::FCmpInst *>;
    Result run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    Result run(llvm::Function &F);
private:
    friend struct llvm::AnalysisInfoMixin<FindFCmpEq>;
    static llvm::AnalysisKey Key;
};


class FindFCmpEqPrinter : public llvm::PassInfoMixin<FindFCmpEqPrinter>{
public:
    explicit FindFCmpEqPrinter(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};

#endif
