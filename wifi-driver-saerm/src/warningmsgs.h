#ifndef WARNINGMSGS_H_
#define WARNINGMSGS_H_

# include "allIncludes.h"

class WarningMessages{
public: 
    static void PositiveConditionMsg(bool, const std::string ) ;
    static void NegativeConditionMsg(bool, const std::string ) ;  
    static void WarningWithoutCrashPositive(bool, const std::string) ; 
    static void TerminatingErrorMessage(std::string);
};

#endif 