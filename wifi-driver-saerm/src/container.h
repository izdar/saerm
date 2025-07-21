#ifndef CONTAINER_H_
#define CONTAINER_H_

# include "allIncludes.h"
# include "warningmsgs.h"

class container
{
public: 
    uint8_t tag;
    uint8_t extension;
    uint8_t length;
    uint16_t *value;
    size_t size;
    bool isTagSet, isExtensionSet, isLengthSet, isValueSet, isSizeSet, isValueAllocated ; 
    container(){};
    bool areAllFieldsAssigned() ; 
    bool isMemoryAllocated() ; 
    
};

#endif 