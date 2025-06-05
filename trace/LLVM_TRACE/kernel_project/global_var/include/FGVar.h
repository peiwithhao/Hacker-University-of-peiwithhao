#ifndef _FGVAR_H
#define _FGVAR_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
// #include "llvm/PassInfo.h"
#include <vector>


namespace llvm {
    //1. AnalysisPass1: Find the Global Variable
    struct GlobalVarFinder : AnalysisInfoMixin<GlobalVarFinder>{
    public:
        using Result = std::vector<GlobalVariable *>;
        Result run(Module &M, ModuleAnalysisManager &);
        void do_globalvar_finder(GlobalVariable &GV, Result &result);
    private:
        friend struct AnalysisInfoMixin<GlobalVarFinder>; 
        static AnalysisKey Key;
    };


    //3. PrintPass1: Print the GLobal Variable
    struct GlobalVarPrinter : PassInfoMixin<GlobalVarPrinter>{
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
        static bool isRequired(){return true;}
    };

}





#endif
