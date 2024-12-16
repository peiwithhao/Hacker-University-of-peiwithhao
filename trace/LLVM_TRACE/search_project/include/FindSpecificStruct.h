#ifndef __FINDSPECIFICSTRUCT_H
#define __FINDSPECIFICSTRUCT_H

#include "llvm/IR/Module.h"
#include <llvm/IR/PassManager.h>
#include <vector>

namespace llvm{
class Module;
class raw_ostream;

}// namespace llvm


/* 寻找特殊结构体 */
class FindSpecificStruct : public llvm::PassInfoMixin<FindSpecificStruct>{
public:
    explicit FindSpecificStruct(llvm::raw_ostream &OutS) : OS(OutS){};
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};

#endif
