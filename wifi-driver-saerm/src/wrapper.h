#ifndef WRAPPER_H_
#define WRAPPER_H_

// #include  "allIncludes.h"

extern "C"{
    # include "driver.h"
    # include "oracle-parser.h"
    # include "replacement.h"
    # include "sendFrame.h"
    #include "sae_assoc.h"
}

# include "connection.h"
# include "warningmsgs.h"
# include "generalutil.h"
# include "pwes.h"
# include <unistd.h>

class SENDWRAPPER
{
    public: 
    static void COMMIT_MESSAGE(sae_context &, connectState *, sae_frame_t&, PWEs&, sae_response& ); 
    static void CONFIRM_MESSAGE(sae_context &, sae_response &, connectState *, sae_frame_t&, PWEs&) ; 
    static void ASSOCIATION_MESSAGE(sae_context &, sae_response &, connectState *, sae_frame_t&) ;
    static void SEND_PROBE_REQUEST(sae_context &, sae_response &, connectState *, sae_frame_t&) ;
    static void RAW_PACKET(sae_context &, sae_response &, connectState *, sae_frame_t&, PWEs&, fuzzer_frame_t&, sae_replacements_t&, std::string&, int &) ; 
    static void DEAUTH_MESSAGE(sae_context &, connectState *) ; 
    static int TEST_CRASH(sae_context &sae_ctx, sae_response & AP_ctx, connectState * connection, sae_frame_t&response);
};
#endif