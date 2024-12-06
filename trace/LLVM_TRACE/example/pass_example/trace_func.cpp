#include "llvm/Bitcode/BitcodeReader.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Support/Error.h"
#include <iostream>
#include <llvm/IR/BasicBlock.h>
#include <memory.h>

using namespace llvm;

/*
 * 这里提供了一个命令行选项，名为Filename，需要提供一个bitcode文件名称，并且在命令行中的位置是重要的
*/
static cl::opt<std::string> FileName(cl::Positional, cl::desc("Bitcode file"), cl::Required);

int main(int argc, char** argv){
    /* 实现命令行接口 */
    cl::ParseCommandLineOptions(argc, argv, "LLVM's Hello world!!!");
    /* 实例化一个LLVMContext对象来存放一次LLVM编译的数据 */
    LLVMContext context;
    std::string error;

    /* 旧版本使用的是OwningPtr来智能化管理内存 */
    ErrorOr<std::unique_ptr<MemoryBuffer>> BufferOrError = MemoryBuffer::getFile(FileName);
    if(!BufferOrError){
        errs() << "Error reading file: " << BufferOrError.getError().message() << "\n";
        return 1;
    }

    /* 结果不是错误 */
    std::unique_ptr<MemoryBuffer> mb = std::move(*BufferOrError);
    
    Expected<std::unique_ptr<Module>> ModuleOrError = parseBitcodeFile(mb->getMemBufferRef(), context);
    if(!ModuleOrError){
        errs() << "Error parseing bitcode \n";
        return 1;
    }
    /* 不是错误 */
    std::unique_ptr<Module> m = std::move(*ModuleOrError);

    /* 引用标准输出 */
    raw_os_ostream O(std::cout);
    for(Module::const_iterator i = m->getFunctionList().begin(), 
        e = m->getFunctionList().end(); i != e; ++i){
        if(!i->isDeclaration()){
            O << i->getName() << " has " << i->size() << " basic block(s). \n";
        }
    }
    O << m->getName() << " has  " << m->getInstructionCount() << "instructions \n";
    return 0;
}


