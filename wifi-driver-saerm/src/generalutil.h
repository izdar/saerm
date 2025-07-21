#ifndef GENERALUTIL_H_
#define GENERALUTIL_H_

# include "allIncludes.h"
# include "warningmsgs.h"

class ManipulationUtility{
    public: 
    static void string_to_unsigned_char(std::string, unsigned char *) ; 
    static unsigned char two_char_to_hexa(char, char) ; 
    static void print_unsigned_char(unsigned char *, size_t ln) ; 
};

#endif 