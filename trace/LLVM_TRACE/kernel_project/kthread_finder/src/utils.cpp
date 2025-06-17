#include "utils.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/IR/Analysis.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include <queue>
#include <system_error>
#include "llvm/Support/FileSystem.h"
using namespace llvm;
// protected from duplicate user
SmallPtrSet<const User *, 32> visited;

std::error_code EC;

llvm::raw_fd_ostream output("myoutput.txt", EC, sys::fs::OpenFlags::OF_None);
llvm::raw_fd_ostream callerfunc("caller.txt", EC, sys::fs::OpenFlags::OF_None);



size_t stack_buffer_level = 0;

// void source_trace_back(llvm::User *user, unsigned int stack_level){
//     if (visited.count(user) || stack_level >= 10) return;
//     visited.insert(user);
//     for(int i = 0; i <= stack_level; ++i){
//         errs() << " ";
//     }
//     user->print(errs());
//     stack_level++;
//     errs() << "\n";
//     for(User *retuser : user->users()){
//         //Store Inst: continue trace the ptr
//         if(StoreInst *store_inst = dyn_cast<StoreInst>(retuser)){
//             // errs() << "\tstore_inst\n";
//             Value *value = store_inst->getPointerOperand();
//             for(User *store_user : value->users()){
//                 source_trace_back(store_user, stack_level);
//             }
//         //Load Inst: cotinue trace self
//         }else if(LoadInst *load_inst = dyn_cast<LoadInst>(retuser)){
//             for(User *load_user : load_inst->users()){
//                 source_trace_back(load_user, stack_level);
//             }
//         }else if(CmpInst *cmp_inst = dyn_cast<CmpInst>(retuser)){
//             // errs() << "\tcmp_inst\n";
//             // icmp_inst->print(errs());
//             // errs() << "\n";
//         }else if(CallBase *call_inst = dyn_cast<CallInst>(retuser)){
//             // errs() << "call_base\n";
//         //PHINode: get Incomming value which include the source chain
//         }else if(PHINode *phi_inst = dyn_cast<PHINode>(retuser)){
//             for (User *phi_user: phi_inst->users()){
//                 source_trace_back(phi_user, stack_level);
//             }
//         //PtrToInt Inst
//         }else if(UnaryInstruction *cast_inst = dyn_cast<UnaryInstruction>(retuser)){
//             for(User *cast_user: cast_inst->users()){
//                 source_trace_back(cast_user, stack_level);
//             }
//         //Select Inst
//         }
//         else if(SelectInst *select_inst = dyn_cast<SelectInst>(retuser)){
//             for(User *select_user: select_inst->users()){
//                 source_trace_back(select_user, stack_level);
//             }
//         //PHINode: get Incomming value which include the source chain
//         }
//         else if(ReturnInst *ret_inst = dyn_cast<ReturnInst>(retuser)){
//             // errs() << "ret_inst" << "\n";
//             Function *ret_func = ret_inst->getFunction();
//             if(ret_func)
//                 FunctionCallerTraverse(*ret_func);
//         //PHINode: get Incomming value which include the source chain
//         }
//         else {
//             errs() << "Unkown Type\n";
//             // retuser->print(errs());
//             // errs() << "\n";
//
//             // if(DebugLoc debuginfo = phi_inst->getDebugLoc()){
//             //     errs() << "debugInfo: " << debuginfo->getDirectory() << "/" << debuginfo->getFilename() << ":" << debuginfo->getLine() << ":" << debuginfo->getColumn() << "\n";
//             // }
//             // DebugLoc debuginfo = phi_inst->getDebugLoc();
//             // retuser->print(errs());
//             // errs() << "\n";
//         }
//     }
// }

void source_trace_back(llvm::User *user, unsigned int stack_level){
    if (visited.count(user) || stack_level >= 10) return;
    visited.insert(user);

    for (int i = 0; i < stack_level; ++i) errs() << " ";
    errs() << "󰘍";
    user->print(errs());
    errs() << "\n";

    // 支持 ConstantExpr
    if (ConstantExpr *ce = dyn_cast<ConstantExpr>(user)) {
        for (User *u : ce->users()) {
            source_trace_back(u, stack_level + 1);
        }
        return;
    }

    for (User *retuser : user->users()) {
        for (int i = 0; i < stack_level; ++i) errs() << " ";
        errs() << "󰘍";
        retuser->print(errs());
        errs() << "\n";
        if (StoreInst *store_inst = dyn_cast<StoreInst>(retuser)) {
            Value *value = store_inst->getPointerOperand();
            if (User *u = dyn_cast<User>(value))
                source_trace_back(u, stack_level + 1);

        } else if (LoadInst *load_inst = dyn_cast<LoadInst>(retuser)) {
            for (User *load_user : load_inst->users())
                source_trace_back(load_user, stack_level + 1);

        } else if (PHINode *phi_inst = dyn_cast<PHINode>(retuser)) {
            for (User *phi_user : phi_inst->users())
                source_trace_back(phi_user, stack_level + 1);
            // for (unsigned i = 0; i < phi_inst->getNumIncomingValues(); ++i) {
            //     Value *v = phi_inst->getIncomingValue(i);
            //     if (User *u = dyn_cast<User>(v))
            //         source_trace_back(u, stack_level + 1);
            // }

        } else if (SelectInst *select_inst = dyn_cast<SelectInst>(retuser)) {
            for (User *select_user : select_inst->users())
                source_trace_back(select_user, stack_level + 1);

        } else if (UnaryInstruction *cast_inst = dyn_cast<UnaryInstruction>(retuser)) {
            for (User *cast_user : cast_inst->users())
                source_trace_back(cast_user, stack_level + 1);

        } else if (ReturnInst *ret_inst = dyn_cast<ReturnInst>(retuser)) {
            Function *ret_func = ret_inst->getFunction();
            if (ret_func)
                FunctionCallerTraverse(*ret_func);

        } else {
            // 未知类型
            if (Instruction *inst = dyn_cast<Instruction>(retuser)) {
                if (DebugLoc debuginfo = inst->getDebugLoc()) {
                    output << "  [dbg] at " << debuginfo->getDirectory()
                           << debuginfo->getFilename()
                           << ":" << debuginfo.getLine()
                           << ":" << debuginfo.getCol() << "\n";
                }
            }
        }
    }
}

// std::vector<Function *> func_vec;


llvm::DenseSet<llvm::Function*> func_visited;

void do_CallerTrace(llvm::Function &func){
    std::queue<Function *> func_q;
    func_q.push(&func);
    while(!func_q.empty()){
        //获取队列头部
        Function *callee_func = func_q.front();
        if(!callee_func->getNumUses()){
            errs() << callee_func->getName() << "\n";
        }
        for(User *user: callee_func->users()){
            if(CallBase *ci = dyn_cast<CallBase>(user)){
                if(Function *ci_func = ci->getFunction()){
                    errs() << "\t" << ci_func->getName() << "\n";
                    if(!func_visited.count(ci_func)){
                        func_visited.insert(ci_func);
                        func_q.push(ci->getFunction());
                    }
                }
            }
        }
        func_q.pop();
    }
}




void FunctionCallerTraverse(llvm::Function &func){
    for(User *user: func.users()){
        errs() << "\033[32m";
        user->print(errs());
        errs() << "\n=================\033[0m\n";
        if(CallInst *ci = dyn_cast<CallInst>(user)){
            source_trace_back(user, 0);
        }else{
            // errs() << "no instruction\n";
            // user->print(errs());
            // errs() <<"\n";
        }
    }
}
