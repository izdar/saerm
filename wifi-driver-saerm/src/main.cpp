extern "C" {
    # include "driver.h" 
    # include "frame_structs.h" 
    # include "h2e.h"
    # include "looping.h" 
    # include "sendFrame.h"
    # include "replacement.h"
    # include "oracle-parser.h"
}
# include "connection.h"
# include "generalutil.h"

#ifdef REPLAYER
    #include "tracereplayer.h"
#endif

#ifdef FUZZER
    # include "fuzzer.h"
#endif
// using namespace std ; 




int main(int argc, char *argv[])
{
    // string s ; 
    // cin >> s ; 
      
    // ManipulationUtility::print_unsigned_char(testmac,6) ; 
    
    if(argc != 10)
    {
        cerr <<"Usage: /fuzzer  SSID  password source-mac dest-mac interfacename physical name input_file_name, output_file_name oracle_file_name" << endl ; 
        WarningMessages::TerminatingErrorMessage("I did not get all the command line arguments I need to run"); 
    }

    unsigned char srcmac [6] ;
    unsigned char destmac [6] ;  
    ManipulationUtility::string_to_unsigned_char(std::string(argv[3]),srcmac);
    ManipulationUtility::string_to_unsigned_char(std::string(argv[4]), destmac) ;

    connectState * connection_state = new connectState() ; 
    connection_state->setConnectionInformation(
        std::string(argv[1]), 
        std::string(argv[2]), 
        std::string(argv[5]), 
        std::string(argv[6]),
        srcmac, 
        destmac 
    );
    connection_state->createSocket() ; 
#ifdef REPLAYER
    TraceReplayer replayThings ; 
    replayThings.setConnectionState(connection_state) ; 
    replayThings.runWholeFile(argv[7], argv[8]); 
    replayThings.freePWE() ;
#endif

#ifdef FUZZER
    Fuzzer fuzzer;
    fuzzer.setConnectionState(connection_state);
    fuzzer.run_fuzzer(argv[7], argv[8], argv[9]);
    // fuzzer.replay_traces(argv[7], argv[8], argv[9]);
    fuzzer.freePWE();
#endif
    connection_state->closeSocket() ; 

    //SSID, password, source-mac, dest-mac, interfacename, physical name
    //input_file_name, output_file_name  
}