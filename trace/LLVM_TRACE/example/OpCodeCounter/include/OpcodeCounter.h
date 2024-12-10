#include "llvm/ADT/StringMap.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"

/* 定义一个类型,感觉有点类似于宏定义 */
using ResultOpcodeCounter = llvm::StringMap<unsigned>;

/* 定义新的PassManager */
struct OpcodeCounter : public llvm::AnalysisInfoMixin<OpcodeCounter>{
    using Result = ResultOpcodeCounter;
    /* 重写的run函数,重点 */
    Result run(llvm::Function &F, llvm::FunctionAnalysisManager &);
    /* 定义新函数 */
    OpcodeCounter::Result generateOpcodeMap(llvm::Function &F);
    /* 表示必须加载 */
    static bool isRequired() {return true;}

private:
    static llvm::AnalysisKey Key;
    friend struct llvm::AnalysisInfoMixin<OpcodeCounter>;
};

/* 定义打印PM */
struct OpcodeCounterPrinter : public llvm::PassInfoMixin<OpcodeCounterPrinter>{
public:
    explicit OpcodeCounterPrinter(llvm::raw_ostream &OutS) : OS(OutS) {};
    using Result = ResultOpcodeCounter;
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    static bool isRequired(){return true;}
private:
    llvm::raw_ostream &OS;
};



