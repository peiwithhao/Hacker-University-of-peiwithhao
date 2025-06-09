#ifndef __CTXFINDER_H
#define __CTXFINDER_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
// #include "llvm/PassInfo.h"
#include <vector>


namespace llvm {
    //1. AnalysisPass1: Find the Global Variable
    struct ctxFinder : AnalysisInfoMixin<ctxFinder>{
    public:
        using Result = std::vector<GlobalVariable *>;
        Result run(Module &M, ModuleAnalysisManager &);
        void do_ctx_finder(GlobalVariable &GV, Result &result);
    private:
        friend struct AnalysisInfoMixin<ctxFinder>; 
        static AnalysisKey Key;
    };


    //3. PrintPass1: Print the GLobal Variable
    struct ctxPrinter : PassInfoMixin<ctxPrinter>{
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
        static bool isRequired(){return true;}
    };

}



#endif
