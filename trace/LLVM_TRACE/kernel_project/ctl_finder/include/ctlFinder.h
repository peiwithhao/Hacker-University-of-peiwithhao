#ifndef __CTLFINDER_H
#define __CTLFINDER_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
// #include "llvm/PassInfo.h"
#include <vector>


namespace llvm {
    //1. AnalysisPass1: Find the Global Variable
    struct ctlFinder : AnalysisInfoMixin<ctlFinder>{
    public:
        using Result = std::vector<GlobalVariable *>;
        Result run(Module &M, ModuleAnalysisManager &);
        void do_ctl_finder(GlobalVariable &GV, Result &result);
        void do_ctl_checker(Result &result);
        void do_constant_parser(Constant &c);
    private:
        friend struct AnalysisInfoMixin<ctlFinder>; 
        static AnalysisKey Key;
    };


    //3. PrintPass1: Print the GLobal Variable
    struct ctlPrinter : PassInfoMixin<ctlPrinter>{
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
        static bool isRequired(){return true;}
    };

}



#endif
