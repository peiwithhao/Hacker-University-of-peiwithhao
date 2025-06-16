#ifndef _KTFINDER_H
#define _KTFINDER_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
// #include "llvm/PassInfo.h"
#include <vector>


namespace llvm {
    //1. AnalysisPass1: Find the Global Variable
    struct KTFinder : AnalysisInfoMixin<KTFinder>{
    public:
        using Result = std::vector<GlobalVariable *>;
        Result run(Module &M, ModuleAnalysisManager &);
    private:
        friend struct AnalysisInfoMixin<KTFinder>; 
        static AnalysisKey Key;
    };


    //3. PrintPass1: Print the GLobal Variable
    struct KTPrinter : PassInfoMixin<KTPrinter>{
    public:
        PreservedAnalyses run(Module &F, ModuleAnalysisManager &);
        static bool isRequired(){return true;}
    };
}





#endif
