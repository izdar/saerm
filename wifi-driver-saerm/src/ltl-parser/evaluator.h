#ifndef EVALUATOR_H_
#define EVALUATOR_H_

# include <iostream> 
# include <vector>
# include <cassert>
# include <cstdlib>
# include <cstring>
# include <algorithm>
# include <map>
# include <set>
# include "ast.h"
# include "typechecker.h"
# include "state.h"
# include "bitvector.h"
# include "memory_manager.h"
# include "ast_printer.h"
using namespace std ;

# define NODE_NOT_NULL(node) ((node) != NULL)
# define BOTH_CHILD_PRESENT(node) (NODE_NOT_NULL(node->binary_left)  && NODE_NOT_NULL((node)->binary_right))
# define LEFT_CHILD_FIXED_TYPE(node, type) ((node)->binary_left->kind == type)
# define RIGHT_CHILD_FIXED_TYPE(node, type) ((node)->binary_right->kind == type)

class Evaluator
{

private: 
    vector<BitVector> new_bv, old_bv ; 
    vector<ASTNode*> formulas ;
    vector<int> serial_numbers ;
    // TypeChecker *Tchecker ;
    int index ; 
    bool EvaluateFormula(ASTNode* node, State *state, size_t iter);
    bool EvaluatePredicate(ASTNode* node, State *state);
    // void Bootstrap(ASTNode * f, int iter) ; 

public:
    Evaluator(vector<ASTNode*> &formulas, vector<int> &snums);
    void reset_evaluator();
    vector<bool> EvaluateOneStep(State *state);

};

#endif 