#ifndef __FINDSTRUCT_H
#define __FINDSTRUCT_H

#include "llvm/IR/Module.h"
#include <llvm/IR/PassManager.h>
#include <vector>

namespace llvm{
class Module;
class raw_ostream;

}// namespace llvm

// class FindStruct : public llvm::AnalysisInfoMixin<FindStruct>{
// public:
//     using Result = std::vector<llvm::StructType *>;
//     Result run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
// private:
//     friend struct llvm::AnalysisInfoMixin<FindStruct>;
//     static struct AnalysisKey Key;
// };

class FindStructPrinter : public llvm::PassInfoMixin<FindStructPrinter>{
public:
    explicit FindStructPrinter(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;

};

#endif
