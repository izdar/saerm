#ifndef TRACEREPLAYER_H_
#define TRACEREPLAYER_H_

extern "C"{
    # include "driver.h"
    # include "oracle-parser.h"
    # include "replacement.h"
    # include "sendFrame.h"
    
}

#include "allIncludes.h"
# include "connection.h"
# include "warningmsgs.h"
# include "wrapper.h"
# include "pwes.h"

enum PacketType {COMMIT, CONFIRM, ASSOCIATION_REQ, RAW}; 
typedef enum PacketType packet_type ; 



class TraceReplayer{
    
    bool isConnectStateAvailable ; 
    bool areFilesOpened ; 
    FILE * fin ; 
    
    public: 
    FILE * fout ; 
    PWEs pwe ; 
    connectState * cstate ; 
    
    TraceReplayer(); 
    void initializePWE(unsigned char *password_identifier) ; 
    void freePWE() ;
    packet_type classifyToken( string &);
    void setConnectionState(connectState *) ; 
    void runASingleTrace( vector<string>&);
    void runWholeFile(char *, char *) ;
    void printBinInHexInFile
    (
        FILE * fout, 
        unsigned char * bin, 
        size_t len
    );


};

#endif 