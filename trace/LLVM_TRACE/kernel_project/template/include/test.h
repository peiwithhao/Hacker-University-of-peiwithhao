#ifndef _TEST_H
#define _TEST_H

#include "llvm/IR/PassManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/GlobalVariable.h"
// #include "llvm/PassInfo.h"
#include <vector>


namespace llvm {
    //1. AnalysisPass1: Find the Global Variable
    struct TemplateAnalyzer : AnalysisInfoMixin<TemplateAnalyzer>{
    public:
        using Result = std::vector<GlobalVariable *>;
        Result run(Module &M, ModuleAnalysisManager &);
    private:
        friend struct AnalysisInfoMixin<TemplateAnalyzer>; 
        static AnalysisKey Key;
    };


    //3. PrintPass1: Print the GLobal Variable
    struct TemplateTransformer : PassInfoMixin<TemplateTransformer>{
    public:
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &);
        static bool isRequired(){return true;}
    };

}





#endif
