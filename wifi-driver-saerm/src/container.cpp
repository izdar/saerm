# include "container.h"

container::container(){
    isTagSet = isExtensionSet = isLengthSet =  isValueSet =  isSizeSet = false ;
}

bool container::areAllFieldsAssigned(){
    return (isTagSet && isExtensionSet && isLengthSet && isValueSet && isSizeSet) ; 
}

bool container::isMemoryAllocated(){
    return this->isValueAllocated ; 
}