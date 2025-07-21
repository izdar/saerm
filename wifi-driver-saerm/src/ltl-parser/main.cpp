// main.cpp
#include <iostream>

#include <fstream>
#include "ast.h"
#include "ast_printer.h"
#include "memory_manager.h"
# include "typechecker.h"
# include "preprocess.h"
# include "evaluator.h"
# include "state.h"

extern FILE *yyin;
extern int yyparse();
extern Spec root;

int main(int argc, char **argv) {
    if (argc > 1) {
        yyin = fopen(argv[1], "r");
        if (!yyin) {
            std::cerr << "Could not open file: " << argv[1] << std::endl;
            return 1;
        }
    } else {
        yyin = stdin;
    }

    if (yyparse() == 0) {
        std::cout << "Parsing successful!" << std::endl;

        TypeChecker typeChecker(root);
        Preprocessor preprocessor;
        vector<int> Serial_Numbers = preprocessor.DoPreProcess(root.second);
        std::cout << ASTPrinter::printStuff(root.second[0]) << std::endl;
        Evaluator evaluator(root.second, Serial_Numbers);
        State state(&typeChecker);
        ASTPrinter::printAST(root.second[0]);
        // bool flag = false ; 
        for(int i = 0 ; i < 2 ; ++i)
        {
            if(i==0){
                state.addLabel("request", "client_commit_success");
                state.addLabel("response", "ap_commit_success");
                
            }
            else{
                state.addLabel("response", "ap_confirm_success");
                state.addLabel("request","requestNotSet");
            }
                assert(state.IsSane());
                cout << "Found state:\n " << state.printState() << std::endl ;
                vector<bool> Results = evaluator.EvaluateOneStep(&state);
                for(auto r : Results)
                {
                    if(!r){
                        std::cerr << "Error: " << "Step " << i << "- Evaluation failed." << std::endl;
                        return 1;
                    }
                }
                state.clearState();
        }
        std::cout << "All evaluations passed." << std::endl;

        
        // Print the AST
        // ASTPrinter::printSpec(root, 0);
        
        // Free memory
        MemoryManager::freeSpec(root);
    } else {
        std::cerr << "Parsing failed." << std::endl;
        return 1;
    }

    if (yyin != stdin) {
        fclose(yyin);
    }

    return 0;
}