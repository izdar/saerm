# include "warningmsgs.h" 


void WarningMessages::PositiveConditionMsg(bool condition, const std::string msg)
{
    if(!condition){
        cerr << "WARNING FROM POSITIVE MSG: " << msg << endl ; 
    }
    assert(condition) ; 

}

void WarningMessages::NegativeConditionMsg(bool condition, const std::string msg)
{
    if(condition){
        cerr << "WARNING FROM NEGATIVE MSG: " << msg << endl ; 
    }
    assert(condition == false) ; 

}

void WarningMessages::WarningWithoutCrashPositive(bool condition, const std::string msg){
    if(!condition) 
        cerr << "WARNING WITHOUT CRASH: " << msg << endl ; 
}

void WarningMessages::TerminatingErrorMessage(const std::string msg)
{
    cerr << "FATAL ERROR: " << msg << endl ; 
    cerr << "TERMINATING PROGRAM" ; 
    exit(1) ; 
}

