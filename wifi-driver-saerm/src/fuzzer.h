#ifndef FUZZER_H_
#define FUZZER_H_

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
#include "evaluator.h"

enum PacketType {COMMIT, CONFIRM, ASSOCIATION_REQ, RAW}; 
typedef enum PacketType packet_type ; 


class Fuzzer{
    
    bool isConnectStateAvailable ; 
    bool areFilesOpened ; 
    FILE * fin ; 
public: 
    FILE * fout ; 
    FILE *oracle_out;
    PWEs pwe ; 
    connectState * cstate ; 
    
    Fuzzer(); 
    void initializePWE(unsigned char *password_identifier) ; 
    void freePWE() ;
    packet_type classifyToken( string &);
    void setConnectionState(connectState *) ; 
    void runASingleTrace( vector<string>&, pair<TypeChecker, vector<int>> &,Evaluator &);
    void run_fuzzer(char *, char *, char *) ;
    void printBinInHexInFile
    (
        FILE * fout, 
        unsigned char * bin, 
        size_t len
    );
    bool check_rejected_groups(fuzzer_frame_t &frame);
    bool check_password_id(fuzzer_frame_t &frame);
    bool check_ac_token_container(fuzzer_frame_t &frame, unsigned char *ac_token);
    bool check_confirm(sae_response &ap_ctx, unsigned char *kck, fuzzer_frame_t &frame, sae_replacements_t &values);
    void state_inference(fuzzer_frame_t &frame, sae_response &AP_ctx);
    void runtime_monitor_dump(vector<bool> &result, vector<string> &trace, vector<string> &response_trace);
    void replay_traces(char * inp_file, char* output_file, char*);
};

#endif