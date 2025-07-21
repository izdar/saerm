# include "generalutil.h"

//local function 

unsigned char hex_digit_to_bin(unsigned char c)
{
    switch(c)
    {
        case '0': case '1': case '2': case '3': 
        case '4': case '5': case '6': case '7': 
        case '8': case '9': return (unsigned char) (c -'0') ; 

        case 'A': case 'B': case 'C' : case 'D' : 
        case 'E' : case 'F' : return (unsigned char) (c - 'A' + 10) ; 

        case 'a': case 'b': case 'c': case 'd' : 
        case 'e': case 'f' : return (unsigned char) (c - 'a'  + 10) ; 
        
        default: WarningMessages::TerminatingErrorMessage("Got weird character during hex to binary conversion") ; return -1 ; 

    }
    WarningMessages::TerminatingErrorMessage("I am in a weird place"); 
    return -1; 
    
}


unsigned char ManipulationUtility::two_char_to_hexa(char c1, char c2)
{
    unsigned char result = 0 ; 
    unsigned char ch1 = hex_digit_to_bin(c1) ; 
    unsigned char ch2 = hex_digit_to_bin(c2) ; 
    result = ((ch1 & 0xFF) << 4) | (ch2 & 0xFF) ; 

    return result ; 
}

void ManipulationUtility::string_to_unsigned_char(std::string input, unsigned char *output)
{
    size_t LEN = input.length() ;
    WarningMessages::PositiveConditionMsg(LEN%2 ==0 , "String length is not an even number :-)") ;
    int j ; 
     
    for(int i = 0, j= 0 ; i < LEN; i +=2, ++j )
    {
        output[j] = ManipulationUtility::two_char_to_hexa(input[i], input[i+1]) ; 
    } 
    return ; 

}

void ManipulationUtility::print_unsigned_char(unsigned char * data, size_t ln)
{
    
    for(int i = 0 ; i < ln ; ++i)
    {
        printf("%02x",data[i]);
    }
    cout << endl ; 
}