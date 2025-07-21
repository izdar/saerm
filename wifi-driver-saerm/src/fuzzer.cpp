#include "fuzzer.h"
#include <sys/stat.h>
#include <unistd.h>
#include "predicate_transformer.h"
#include "state.h"
#include "evaluator.h"
#include "typechecker.h"
#include "preprocess.h"
#include "ast.h"
#include "parser.h"
#include "ast_printer.h"
#include <chrono>
#include <sys/types.h>
#include <signal.h>

extern FILE* yyin;
extern int yyparse();
extern Spec root;

Fuzzer::Fuzzer()
{
    this->isConnectStateAvailable = false ;
    this->areFilesOpened = false ;
    this->fin = this->fout = NULL ;
}

pair<TypeChecker, vector<int>> parse_spec(char* filename) {
    // Open the file
    FILE* file = fopen(filename, "r");
    if (!file) {
        std::cerr << "Could not open file: " << filename << std::endl;
        throw std::runtime_error("File opening failed");
    }
    
    // Set yyin to the opened file
    yyin = file;
    
    // Parse the file
    if (yyparse() == 0) {
        std::cout << "Parsing successful!" << std::endl;
        
        // Create TypeChecker and Preprocessor objects
        TypeChecker typeChecker(root);
        Preprocessor preprocessor;
        vector<int> Serial_Numbers = preprocessor.DoPreProcess(root.second);
        // ASTPrinter p;
        // for (auto &i : root.second) {
        //     p.printAST(i);
        // }

        // Close the file before returning
        fclose(file);
        // exit(0);       
        // Return the pair
        return std::make_pair(typeChecker, Serial_Numbers);
    } else {
        // Close the file before throwing an exception
        fclose(file);
        std::cerr << "Parsing failed." << std::endl;
        throw std::runtime_error("Parsing error");
    }
}


void Fuzzer::setConnectionState(connectState * cinput)
{
    WarningMessages::PositiveConditionMsg(cinput != NULL, "The input connection you are giving me is NULL"); 
    this->cstate = cinput ; 
    this->isConnectStateAvailable = true ; 
    this->initializePWE(NULL) ; 
}

packet_type Fuzzer::classifyToken( string &raw_token)
{
    if(raw_token == "COMMIT") return COMMIT ; 
    else if(raw_token == "CONFIRM") return CONFIRM ; 
    else if(raw_token=="ASSOCIATION_REQUEST") return ASSOCIATION_REQ ; 
    return RAW ; 
}

void Fuzzer::printBinInHexInFile
(
    FILE * fout, 
    unsigned char * bin, 
    size_t len
)
{
    if(fout == NULL) assert(0) ; 

    WarningMessages::PositiveConditionMsg(fout != NULL, "The output file handler is null"); 
    // fprintf(fout,"%u",len);
    printf("DATA LEN = %u\n", len) ; 
    // for(size_t i = 0; i < len; ++i)
    // {
    //     // if((bin+i))fprintf(fout, "%02x", bin[i]) ;
    //     fprintf(fout,"AA"); 
    // }
    // fprintf(fout, "\n") ; 
    return ; 
}

void FIELD_REPLACER_ALLOCATE(sae_replacements_t &fieldReplacer){
    fieldReplacer.scalar = (unsigned char*) malloc(32) ;
    fieldReplacer.element = (unsigned char*) malloc(64) ;
    fieldReplacer.ac_token = (unsigned char*) malloc(35) ;
    fieldReplacer.send_confirm = (unsigned char*) malloc(2) ;
    fieldReplacer.confirm_hash = (unsigned char*) malloc(32) ;
    WarningMessages::PositiveConditionMsg(fieldReplacer.scalar != NULL && fieldReplacer.element != NULL
    && fieldReplacer.ac_token != NULL && fieldReplacer.send_confirm != NULL && fieldReplacer.confirm_hash != NULL, 
"Field Replacer allocation failed in running a whole trace. Likely out of memory.");

}
void FIELD_REPLACER_FREE(sae_replacements_t &fieldReplacer)
{
    // WarningMessages::PositiveConditionMsg(fieldReplacer.scalar != NULL && fieldReplacer.element != NULL
    //     && fieldReplacer.ac_token != NULL && fieldReplacer.send_confirm != NULL && fieldReplacer.confirm_hash != NULL, 
    // "During deallocation found one of the allocated fields to be NULL. Someone else may have deallocated them.");
    if(fieldReplacer.scalar)free(fieldReplacer.scalar);
    if(fieldReplacer.element) free(fieldReplacer.element) ; 
    if(fieldReplacer.ac_token) free(fieldReplacer.ac_token) ; 
    if(fieldReplacer.send_confirm)free(fieldReplacer.send_confirm) ; 
    if(fieldReplacer.confirm_hash) free(fieldReplacer.confirm_hash) ; 
    fieldReplacer.scalar = NULL ;
    fieldReplacer.element = NULL ;
    fieldReplacer.ac_token = NULL ;
    fieldReplacer.send_confirm = NULL ;
    fieldReplacer.confirm_hash = NULL ;
    

}

void SAE_CTX_FREE(sae_context& sae_ctx)
{
    WarningMessages::PositiveConditionMsg(
        sae_ctx.ssid != NULL && 
        sae_ctx.password != NULL && 
        sae_ctx.group != NULL && 
        sae_ctx.rand != NULL && 
        sae_ctx.mask != NULL && 
        sae_ctx.scalar != NULL && 
        sae_ctx.element != NULL && 
        sae_ctx.confirm != NULL && 
        sae_ctx.pwe != NULL && 
        sae_ctx.kck != NULL && 
        sae_ctx.pmk != NULL && 
        sae_ctx.pmk_id != NULL && 
        sae_ctx.ptk != NULL && 
        sae_ctx.eapol_kck != NULL && 
        sae_ctx.nonce != NULL, 
        "Problem in Deallocating SAE_CTX. One or more fields have been deallocated already."
    );    
    printf("\n\n==============INITIATING FREES===================\n\n");
    printf("---------------Trying to free SSID---------------\n");
    free(sae_ctx.ssid) ; 
    printf("---------------Trying to free PASSWORD---------------\n");
    free(sae_ctx.password) ; 
    printf("---------------Trying to free SCALAR---------------\n");
    BN_free(sae_ctx.scalar) ; 
    printf("---------------Trying to free RAND---------------\n");
    BN_free(sae_ctx.rand) ; 
    printf("---------------Trying to free MASK---------------\n");
    BN_free(sae_ctx.mask) ; 
    printf("---------------Trying to free element---------------\n");
    EC_POINT_free(sae_ctx.element) ;
    printf("---------------Trying to free CONFIRM---------------\n");
    free(sae_ctx.confirm);
    // // EC_POINT_free(sae_ctx.pwe) ; 
    printf("---------------Trying to free KCK---------------\n");
    free(sae_ctx.kck) ; 
    printf("---------------Trying to free PMK---------------\n");
    free(sae_ctx.pmk) ; 
    free(sae_ctx.pmk_id) ; 
    printf("---------------Trying to free PTK---------------\n");
    free(sae_ctx.ptk) ; 
    printf("---------------Trying to free EAPOL---------------\n");
    free(sae_ctx.eapol_kck) ; 
    printf("---------------Trying to free NONCE---------------\n");
    free(sae_ctx.nonce) ; 
    // EC_GROUP_free(sae_ctx.group) ; 
    printf("---------------Trying to free RG_CONTAINER-----------------\n");
    if (sae_ctx.rg_container.value) free(sae_ctx.rg_container.value);
    printf("---------------Trying to free PI_CONTAINER-----------------\n");
    if (sae_ctx.pi_container.value) free(sae_ctx.pi_container.value);
    printf("---------------Trying to free AC_CONTAINER-----------------\n");
    if (sae_ctx.ac_container.value) free(sae_ctx.ac_container.value);

    printf("\n===============DONE WITH FREES=======================\n\n");


    // sae_ctx.group = NULL ;
    sae_ctx.ssid = NULL ;
    sae_ctx.password = NULL ;
    sae_ctx.rand = NULL ;
    sae_ctx.mask = NULL ;
    sae_ctx.scalar = NULL ;
    sae_ctx.element = NULL ;
    sae_ctx.confirm = NULL ;
    sae_ctx.pwe = NULL ;
    sae_ctx.kck = NULL ;
    sae_ctx.pmk = NULL ;
    sae_ctx.pmk_id = NULL ;
    sae_ctx.ptk = NULL ;
    sae_ctx.eapol_kck = NULL ;
    sae_ctx.nonce = NULL ;
    sae_ctx.areKeysSet = false ;
    sae_ctx.ac_token_set = false ;
    sae_ctx.eapol_replay_counter = 0 ;
    sae_ctx.send_confirm = 0 ;
    sae_ctx.rg_container.value = NULL ;
    sae_ctx.rg_container.size = 0 ;
    sae_ctx.rg_container.length = 0 ;
    sae_ctx.rg_container.extension = 0 ;
    sae_ctx.rg_container.tag = 0 ;
    sae_ctx.pi_container.value = NULL ;
    sae_ctx.pi_container.size = 0 ;

}

void AP_CTX_INITIALIZE(EC_GROUP *group, sae_response& AP_CTX)
{
    AP_CTX.scalar = BN_new(); 
    AP_CTX.status = -1;
    AP_CTX.ac_token = (unsigned char*) malloc(35 * sizeof(unsigned char)) ; 
    AP_CTX.group = group;
    AP_CTX.group_id = -1;
    AP_CTX.element = EC_POINT_new(AP_CTX.group) ; 
    AP_CTX.nonce = (unsigned char*) malloc(32 * sizeof(unsigned char)) ;
    AP_CTX.isZeroElement = true ;
    WarningMessages::PositiveConditionMsg(AP_CTX.scalar != NULL && 
    AP_CTX.ac_token != NULL && 
    AP_CTX.group != NULL && 
    AP_CTX.element != NULL && 
    AP_CTX.nonce != NULL, 
    "INitializing AP_CTX Failed"
    );
    
}

void initialize_fuzzer_frame(fuzzer_frame_t& frame) {
    // Initialize fixed fields
    frame.algo = 0;
    frame.seq = 0;
    frame.status_code = 0;
    frame.group_id = 0;
    
    // Initialize Commit frame fields
    frame.ac_token = nullptr;
    frame.ac_token_len = 0;
    frame.ac_token_present = false;
    frame.ac_token_is_placeholder = false;
    
    frame.scalar = nullptr;
    frame.scalar_len = 0;
    frame.scalar_present = false;
    frame.scalar_is_placeholder = false;
    
    frame.element = nullptr;
    frame.element_len = 0;
    frame.element_present = false;
    frame.element_is_placeholder = false;
    
    // Initialize Container fields
    frame.password_id = nullptr;
    frame.password_id_len = 0;
    frame.password_id_present = false;
    
    frame.rejected_groups = nullptr;
    frame.rejected_groups_len = 0;
    frame.rejected_groups_present = false;
    
    frame.ac_token_container = nullptr;
    frame.ac_token_container_len = 0;
    frame.ac_token_container_present = false;
    
    // Initialize Confirm frame fields
    frame.send_confirm = nullptr;
    frame.send_confirm_len = 0;
    frame.send_confirm_present = false;
    frame.send_confirm_is_placeholder = false;
    
    frame.confirm_hash = nullptr;
    frame.confirm_hash_len = 0;
    frame.confirm_hash_present = false;
    frame.confirm_hash_is_placeholder = false;
    
    // Initialize EAPOL Key frame fields
    frame.nonce = nullptr;
    frame.nonce_len = 0;
    frame.nonce_present = false;
    frame.nonce_is_placeholder = false;
    
    frame.counter = nullptr;
    frame.counter_len = 0;
    frame.counter_present = false;
    frame.counter_is_placeholder = false;
    
    frame.mic = nullptr;
    frame.mic_len = 0;
    frame.mic_present = false;
    frame.mic_is_placeholder = false;
    
    // Initialize EAPOL Key2 specific fields
    frame.rsn_ie = nullptr;
    frame.rsn_ie_len = 0;
    frame.rsn_ie_present = false;
    frame.rsn_ie_is_placeholder = false;
    
    // Initialize EAPOL Key3 specific fields
    frame.gtk = nullptr;
    frame.gtk_len = 0;
    frame.gtk_present = false;
    frame.gtk_is_placeholder = false;
    
    // Initialize EAPOL Key4 specific fields
    frame.install_key_flag = nullptr;
    frame.install_key_flag_len = 0;
    frame.install_key_present = false;
    frame.install_key_is_placeholder = false;
    
    frame.secure_bit = nullptr;
    frame.secure_bit_len = 0;
    frame.secure_bit_present = false;
    frame.secure_bit_is_placeholder = false;
}

void AP_CTX_FREE(sae_response& AP_CTX)
{
    WarningMessages::PositiveConditionMsg(AP_CTX.scalar != NULL && 
    AP_CTX.ac_token != NULL && 
    AP_CTX.group != NULL && 
    AP_CTX.element != NULL && 
    AP_CTX.nonce != NULL, 
    "FREEING AP_CTX Failed"
    );

    BN_free(AP_CTX.scalar);
    free(AP_CTX.ac_token) ; 
    EC_POINT_free(AP_CTX.element);
    // EC_GROUP_free(AP_CTX.group) ; 
    free(AP_CTX.nonce) ;     
    AP_CTX.scalar = NULL ;
    AP_CTX.ac_token = NULL ;
    // AP_CTX.group = NULL ;
    AP_CTX.element = NULL ;
    AP_CTX.nonce = NULL ;
}

void Fuzzer_FRAME_T_FREE(fuzzer_frame_t& frame) {
    if(frame.ac_token) free(frame.ac_token);
    if(frame.scalar) free(frame.scalar);
    if(frame.element) free(frame.element);
    if(frame.password_id) free(frame.password_id);
    if(frame.rejected_groups) free(frame.rejected_groups);
    if(frame.ac_token_container) free(frame.ac_token_container);
    if(frame.send_confirm) free(frame.send_confirm);
    if(frame.confirm_hash) free(frame.confirm_hash);
}

bool Fuzzer::check_rejected_groups(fuzzer_frame_t &frame) {
    if(!frame.rejected_groups_present) return true;
    if(frame.rejected_groups == NULL) return true;
    for(size_t i = 0; i < frame.rejected_groups_len; ++i) {
        if(frame.rejected_groups[i] == 19 || frame.rejected_groups[i] == 20 || frame.rejected_groups[i] == 21) {
            return false;
        }
    }
    return true;
}

bool Fuzzer::check_password_id(fuzzer_frame_t &frame) {
    if (frame.password_id_present) return false;
    return true;
}

bool Fuzzer::check_ac_token_container(fuzzer_frame_t &frame, unsigned char *ac_token) {
    if (ac_token == NULL && frame.ac_token_container_present) return false;
    if(frame.ac_token_container_present) {
        if (ac_token == NULL && frame.ac_token_container == NULL) return true;
        if(frame.ac_token_container_len != 35) return false;
        else {
            for (size_t i = 0; i < frame.ac_token_container_len; ++i) {
                if (frame.ac_token_container[i] != ac_token[i]) return false;
            }
        }
    }
    return true;
}

bool Fuzzer::check_confirm(sae_response &ap_ctx, unsigned char *kck, fuzzer_frame_t &frame, sae_replacements_t &values) {
    size_t data_len = sizeof(uint16_t) + 32 + 64 + 32 + 64 ;
    unsigned char *data = (unsigned char *) malloc(data_len);

    size_t pos = 0;
    memcpy(data, &ap_ctx.send_confirm, 16);
    pos += 2;

    BN_bn2binpad(ap_ctx.scalar, data + pos, 32);
    pos += 32;

    unsigned char element_buf[65];
    size_t element_len = EC_POINT_point2oct(ap_ctx.group, ap_ctx.element, POINT_CONVERSION_UNCOMPRESSED, element_buf, 65, NULL);
    memcpy(data + pos, element_buf + 1, 64);
    pos += 64;

    if(frame.scalar_is_placeholder) {
        memcpy(data + pos, values.scalar, 32);
        pos += 32;
    } else {
        goto fail;
    }

    if(frame.element_is_placeholder) {
        memcpy(data + pos, values.element, 64);
        pos += 64;
    } else {
        goto fail;
    }
    unsigned char expected_confirm[32];
    hmac256(kck, 32, data, data_len, expected_confirm);

    for (size_t i = 0; i < 32; ++i) {
        if (expected_confirm[i] != ap_ctx.confirm[i]) return false;
    }

    return true;

fail:
    free(data);
    data = nullptr;
    return false;
}

void Fuzzer::state_inference(fuzzer_frame_t &frame, sae_response &AP_ctx) {
    if (frame.algo == 3) {
        if (frame.seq == 1) {
            if (frame.group_id != 19 && frame.group_id != 20 && frame.group_id != 21){
                fprintf(this->oracle_out, "NOTHING");
            }
            else if (frame.scalar_present && 
                frame.scalar_is_placeholder && 
                frame.element_present &&
                frame.element_is_placeholder) {
                // SCALAR VALID, ELEMENT VALID, CHECK CONTAINERS
                bool rg_valid = Fuzzer::check_rejected_groups(frame);
                bool pi_valid = Fuzzer::check_password_id(frame);
                bool ac_valid = Fuzzer::check_ac_token_container(frame, AP_ctx.ac_token);
                if (!rg_valid || !pi_valid || !ac_valid || 
                    frame.status_code != 0 || 
                    frame.status_code != 126 || 
                    frame.algo != 3 || 
                    frame. seq != 1) {
                    fprintf(this->oracle_out, "CONFIRMED");
                } else {
                    fprintf(this->oracle_out, "NOTHING");
                }
            } else {
                fprintf(this->oracle_out, "NOTHING");
            }
        }
        else if (frame.seq == 2) {
            if (AP_ctx.scalar && AP_ctx.element) {
                if (frame.confirm_hash_is_placeholder && frame.send_confirm_is_placeholder) {
                    fprintf(this->oracle_out, "ACCEPTED");
                } else {
                    fprintf(this->oracle_out, "IGNORE");
                }
            } else {
                fprintf(this->oracle_out, "IGNORE");
            }
        } else {
            fprintf(this->oracle_out, "IGNORE");
        }
    } else {
        fprintf(this->oracle_out, "IGNORE");
    }
    fflush(this->oracle_out);
}

void Fuzzer::runtime_monitor_dump(vector<bool> &result, vector<string> &trace, vector<string> &response_trace) {
    size_t formula_size = result.size();
    std::string out;
    for (int i = 0; i < formula_size; ++i) {
        if (!result[i]) {
            out += to_string(i) + " ";
        }
    }
    if (out.size() > 0) {
        std::string str_trace;
        size_t str_trace_size = trace.size();
        for (size_t i = 0; i < str_trace_size; ++i) str_trace += "(" + trace[i] + ", " + response_trace[i] + ")" + " ";
        FILE *file = fopen("runtime_monitor.txt", "a");
        fprintf(file, out.c_str());
        fprintf(file, str_trace.c_str());
        fprintf(file, "\n");
        fclose(file);
    }
}

std::string binaryToHexString(const unsigned char* data, size_t length) {
    static const char hexChars[] = "0123456789abcdef";
    std::string result;
    result.reserve(length * 2);
    
    for (size_t i = 0; i < length; ++i) {
        unsigned char byte = data[i];
        result.push_back(hexChars[byte >> 4]);
        result.push_back(hexChars[byte & 0x0F]);
    }
    return result;
}

void Fuzzer::runASingleTrace(vector<string>& trace, pair<TypeChecker, vector<int>> &spec_and_serial, Evaluator &eval)
{
    sae_context sae_ctx ;
    sae_response AP_ctx ; 
    sae_frame_t response ; 
    sae_replacements_t fieldReplacer ;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    fuzzer_frame_t  parsingHandler ; 
    PredicateTransformer transformer;

    vector<string> response_trace;
    int prev_ap_group = -1;
    int prev_ap_send_confirm = -1;
    initialize_sae_context(group, (unsigned char *)cstate->getSSID().c_str(), cstate->destMAC, &sae_ctx) ; 
    AP_CTX_INITIALIZE(group, AP_ctx) ;
    
    initialize_fuzzer_frame(parsingHandler);
    // AP_ctx.scalar = BN_new() ;
    // AP_ctx.element = EC_POINT_new(sae_ctx.group);
    response.type = OTHER;
    // Allocation happening here ... 
    FIELD_REPLACER_ALLOCATE(fieldReplacer) ; 
    

    size_t trace_length = trace.size();
    bool lastPacketWasRaw = false ;
    // SENDWRAPPER::SEND_PROBE_REQUEST(sae_ctx, AP_ctx, cstate, response);
    for(size_t i = 0 ; i < trace_length; ++i)
    {
        int parser_error_code = 1;
        std::string response_hex;
        State ltl_state(&spec_and_serial.first);
        
        switch(classifyToken(trace[i])){
            case COMMIT : 
                SENDWRAPPER::COMMIT_MESSAGE(sae_ctx, cstate, response, pwe, AP_ctx);
                if (response.data && response.data_len && response.type == COMMIT) prev_ap_group = AP_ctx.group_id;
                transformer.predicate_transform(COMMIT, sae_ctx, AP_ctx, parsingHandler, response, ltl_state, prev_ap_group, prev_ap_send_confirm, 1);
                if (response.data && response.data_len) {
                    response_hex = binaryToHexString(response.data, response.data_len);
                    response_trace.push_back(response_hex);
                    free(response.data) ;
                    response.data = nullptr;
                    response.data_len = 0;
                } else {response_trace.push_back("timeout");}
                WarningMessages::WarningWithoutCrashPositive(false, "we made it here after commit");
                break ; 
            case CONFIRM: 
                sae_ctx.send_confirm = 1;
                SENDWRAPPER::CONFIRM_MESSAGE(sae_ctx, AP_ctx, cstate, response, pwe) ;
                if (response.data && response.data_len && response.type == CONFIRM) prev_ap_send_confirm = AP_ctx.send_confirm;
                transformer.predicate_transform(CONFIRM, sae_ctx, AP_ctx, parsingHandler, response, ltl_state, prev_ap_group, prev_ap_send_confirm, 1);
                if (response.data && response.data_len) {
                    response_hex = binaryToHexString(response.data, response.data_len);
                    response_trace.push_back(response_hex);
                    free(response.data) ;
                    response.data_len = 0;
                    response.data = nullptr;
                } else {response_trace.push_back("timeout");}
                break ; 
            case ASSOCIATION_REQ: 
                if (response.data && response.data_len) {
                    free(response.data);
                    response.data_len = 0;
                    response.data = nullptr;
                }
                SENDWRAPPER::ASSOCIATION_MESSAGE(sae_ctx, AP_ctx, cstate, response);
                transformer.predicate_transform(ASSOCIATION_REQ, sae_ctx, AP_ctx, parsingHandler, response, ltl_state, prev_ap_group, prev_ap_send_confirm, 1); 
                if (response.data && response.data_len) {
                    response_hex = binaryToHexString(response.data, response.data_len);
                    response_trace.push_back(response_hex);
                    free(response.data);
                    response.data = nullptr;
                    response.data_len = 0;
                } else if (response.type == ASSOC_RESPONSE) {
                    response_trace.push_back("ASSOCIATION_RESPONSE");
                }
                else {response_trace.push_back("timeout");}
                break ; 
            case RAW: 
                sae_ctx.send_confirm = 1;
                SENDWRAPPER::RAW_PACKET(sae_ctx, AP_ctx, cstate, response, pwe, parsingHandler, fieldReplacer, trace[i], parser_error_code);
                if (response.data && response.data_len && response.type == COMMIT) prev_ap_group = AP_ctx.group_id;
                if (response.data && response.data_len && response.type == CONFIRM && AP_ctx.status == 0) prev_ap_group = AP_ctx.send_confirm;
                transformer.predicate_transform(RAW, sae_ctx, AP_ctx, parsingHandler, response, ltl_state, prev_ap_group, prev_ap_send_confirm, parser_error_code);
                if (response.data && response.data_len > 0 && response.type != TIMEOUT) {
                    response_hex = binaryToHexString(response.data, response.data_len);
                    response_trace.push_back(response_hex);
                } else { response_trace.push_back("timeout"); }
                if (i != trace_length - 1) {
                    Fuzzer_FRAME_T_FREE(parsingHandler);
                }
                else {
                    lastPacketWasRaw = true ;
                }
                break ; 
            default: 
                WarningMessages::TerminatingErrorMessage("weird default case in runASingleTrace") ; 
                break; 
        }
        
        vector<bool> runtime_monitor_result = eval.EvaluateOneStep(&ltl_state);
        if (i >= trace_length - 1) {
            runtime_monitor_dump(runtime_monitor_result, trace, response_trace);
        }
        if (i >= trace_length - 1 && lastPacketWasRaw) {
            state_inference(parsingHandler, AP_ctx);
            if (response.type == SAE_COMMIT) {
                if (parsingHandler.group_id != 19 && parsingHandler.group_id != 20 && parsingHandler.group_id != 21){
                    // UNSUPPORTED_CYCLIC_GROUP
                    if(AP_ctx.status == 77) {
                        printf("[Logging] AP COMMIT STATUS CODE: %d\n", AP_ctx.status);
                        fprintf(this->fout, "EXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                    else if (AP_ctx.status == 0 || AP_ctx.status == 126) {
                        fprintf(this->fout, "UNEXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                    else {
                        fprintf(this->fout, "EXPECTED_OUTPUT");
                    }
                }
                else if (parsingHandler.scalar_present && 
                    parsingHandler.scalar_is_placeholder && 
                    parsingHandler.element_present &&
                    parsingHandler.element_is_placeholder) {
                    // SCALAR VALID, ELEMENT VALID, CHECK CONTAINERS
                    bool rg_valid = Fuzzer::check_rejected_groups(parsingHandler);
                    bool pi_valid = Fuzzer::check_password_id(parsingHandler);
                    bool ac_valid = Fuzzer::check_ac_token_container(parsingHandler, AP_ctx.ac_token);
                    if (
                        (AP_ctx.status == 0 || AP_ctx.status == 126) && 
                        (!rg_valid || !pi_valid || !ac_valid || 
                        parsingHandler.status_code != 0 || 
                        parsingHandler.status_code != 126 || 
                        parsingHandler.algo != 3 || 
                        parsingHandler. seq != 1)
                    ) {
                        fprintf(this->fout, "UNEXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                    else {
                        fprintf(this->fout, "EXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                } else if (AP_ctx.status != 0 && AP_ctx.status != 126){
                    fprintf(this->fout, "EXPECTED_OUTPUT");
                    fflush(this->fout);
                } else {
                    fprintf(this->fout, "UNEXPECTED_OUTPUT");
                    fflush(this->fout);
                }
            }
            else if (response.type == SAE_CONFIRM) {
                if (AP_ctx.status == 0) {
                    // verify 2 things: (1) your confirm and (2) the AP confirm
                    if (!Fuzzer::check_confirm(AP_ctx, sae_ctx.kck, parsingHandler, fieldReplacer)) {
                        fprintf(this->fout, "UNEXPECTED_OUTPUT");
                        fflush(this->fout);
                    } else {
                        fprintf(this->fout, "EXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                } else {
                    // verify whether you sent a valid confirm
                    if(sae_ctx.areKeysSet && 
                        parsingHandler.confirm_hash_is_placeholder && 
                        parsingHandler.send_confirm_is_placeholder) {
                            fprintf(this->fout, "UNEXPECTED_OUTPUT");
                            fflush(this->fout);
                        } else {
                        fprintf(this->fout, "EXPECTED_OUTPUT");
                        fflush(this->fout);
                    }
                }
            }
            else if (response.type == ASSOC_RESPONSE) {
                // check valid state transition, is a commit/confirm missing?
                // on second thought.. if random bytes cause this, flag it.
                fprintf(this->fout, "UNEXPECTED_OUTPUT");
                fflush(this->fout);
            }
            else if (response.type == TIMEOUT) {
                // check whether you timed out or crashed.. (just check whether the AP is still broadcasting or commit trick)
                if (SENDWRAPPER::TEST_CRASH(sae_ctx, AP_ctx, cstate, response) < 0) {
                    fprintf(this->fout, "CRASH");
                    fflush(this->fout);
                }
                else {
                    fprintf(this->fout, "TIMEOUT");            
                    fflush(this->fout);
                }   
            }
            else {
                printf("Strange response type..\n");
                fprintf(this->fout, "UNEXPECTED_OUTPUT");
                fflush(this->fout);
            }
            Fuzzer_FRAME_T_FREE(parsingHandler);
        }
        else if (i >= trace_length - 1) {
            fprintf(this->fout, "SUCCESSFUL_TRANSITION_SUCCESS");
            fflush(this->fout);
        }
        if (response.data && response.data_len) {
            free(response.data) ;
            response.data = nullptr;
            response.data_len = 0;
        }
        if (lastPacketWasRaw && ftell(this->fout) == 0) {
            printf("[Warning] No output was written to fout — possibly malformed trace.\n");
            printf("[RESPONSE_TYPE] %d\n", response.type);
            printf("[Logging] Value of i/len: %d %d\n", i, trace_length - 1);
        }
        ltl_state.clearState();
    }
    SENDWRAPPER::DEAUTH_MESSAGE(sae_ctx, cstate); //done sending a deauth message 
    //Deallocation will happen here 
    FIELD_REPLACER_FREE(fieldReplacer) ; 
    // Fuzzer_FRAME_T_FREE(parsingHandler);
    SAE_CTX_FREE(sae_ctx) ; 
    AP_CTX_FREE(AP_ctx) ; 
}


void tokenizeALine(char * raw_line, vector<string> &tokens)
{
    char * p ; 
    tokens.clear() ; 
    p = strtok(raw_line, ", \n") ; 
    while(p){
        tokens.push_back(std::string(p)) ; 
        p = strtok(NULL, " ,\n") ; 
    }
}

void Fuzzer::initializePWE(unsigned char *password_identifier){ 
    this->pwe.group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    this->pwe.PT = hash_to_element((unsigned char*) cstate->getPassword().c_str(), (unsigned char*) cstate->getSSID().c_str(), password_identifier, this->pwe.group);
    this->pwe.h2e_PWE = EC_POINT_new(this->pwe.group) ;
    BN_CTX *ctx = BN_CTX_new();
    calculate_pwe(this->pwe.PT, (unsigned char*)cstate->destMAC, (unsigned char*)cstate->sourceMAC, this->pwe.h2e_PWE, this->pwe.group) ;
    BIGNUM *prime = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    EC_GROUP_get_curve_GFp(this->pwe.group, prime, a, b, NULL);
    // this->loop_PWE = EC_POINT_new(group) ; 
    this->pwe.loop_PWE = derive_pwe_looping(this->pwe.group, (unsigned char*)cstate->getPassword().c_str(),
    (unsigned char*) cstate->sourceMAC, (unsigned char*)cstate->destMAC, prime, b, 256);
    BN_free(prime);
    BN_free(a) ; 
    BN_free(b) ; 
    BN_CTX_free(ctx) ; 


} 

void Fuzzer::freePWE()
{
    WarningMessages::PositiveConditionMsg(
        this->pwe.group != NULL && 
        this->pwe.PT != NULL && 
        this->pwe.h2e_PWE != NULL && //OMAR: unsure about this 
        this->pwe.loop_PWE != NULL, //OMAR: UNSURE ABOUT THIS
    "Someone already has deallocated PWE inside trace replayer"
    );
    EC_GROUP_free(this->pwe.group) ; 
    EC_POINT_free(this->pwe.PT) ; 
    EC_POINT_free(this->pwe.h2e_PWE) ; 
    EC_POINT_free(this->pwe.loop_PWE) ; 
    this->pwe.group = NULL ;
    this->pwe.PT = NULL ;
    this->pwe.h2e_PWE = NULL ;
    this->pwe.loop_PWE = NULL ;
}

bool fileNotEmpty(const char* filename) {
    struct stat st;
    if (stat(filename, &st) != 0) return false;
    return st.st_size > 0;
}

bool runCommand(const std::string& command, pid_t& childPid) {
    pid_t pid = fork();

    if (pid == -1) {
        std::cerr << "Failed to fork\n";
        return false;
    }

    if (pid == 0) {
        // Child process
        execl("/bin/sh", "sh", "-c", command.c_str(), (char *) nullptr);
        // If execl fails
        std::cerr << "Failed to exec\n";
        exit(1);
    } else {
        // Parent process
        childPid = pid;
        std::cout << "Spawned process with PID: " << childPid << "\n";
        return true;
    }
}

// Function to kill the subprocess
bool killCommand(pid_t& childPid) {
    if (childPid > 0) {
        if (kill(childPid, SIGTERM) == 0) {
            std::cout << "Process " << childPid << " terminated\n";
            childPid = -1;
            return true;
        } else {
            perror("Failed to kill process");
            return false;
        }
    } else {
        std::cerr << "No active process to kill\n";
        return false;
    }
}

void Fuzzer::run_fuzzer(char * inp_file, char * output_file, char* oracle_response_file)
{ 
    printf("parsing specification..\n");
    std::pair<TypeChecker, vector<int>> spec_and_serial = parse_spec("ltl-parser/specification.txt");
    printf("specification parsed!\n");
    Evaluator eval(root.second, spec_and_serial.second);
    printf("Evaluator created.\n");
    // std::string hostapd = "sudo ../../hostap-wpa3/hostapd/hostapd -dd -K ../../hostap-wpa3/hostapd/hostapd_wpa3.conf";
// #ifdef HOSTAPD
//     auto start = std::chrono::steady_clock::now();
//     pid_t childPid = -1;
//     if (!runCommand(hostapd, childPid)){
//         perror("we got a problem");
//     }
// #endif
    while(1)
    {
// #ifdef HOSTAPD
//         if (std::chrono::steady_clock::now() - start >= std::chrono::minutes(10)) {
//             killCommand(childPid);
//             runCommand(hostapd, childPid);
//             start = std::chrono::steady_clock::now();
//         }
// #endif
        this->areFilesOpened = true ; 
        while (!fileNotEmpty(inp_file)) {
            usleep(100000);
        }
        this->fout = fopen(output_file, "w") ; 
        this->oracle_out = fopen(oracle_response_file, "w");
        WarningMessages::PositiveConditionMsg(this->fout != NULL, "Couldn't open output file") ; 
        WarningMessages::PositiveConditionMsg(this->isConnectStateAvailable, "There is no connection state"); 
        char line[100000] ; 
        this->fin = fopen(inp_file, "r") ;
        WarningMessages::PositiveConditionMsg(this->fin != NULL, "Couldn't open input file"); 
        vector<string> tokens; 
        if (fgets(line,sizeof(line),fin)) {
            tokenizeALine(line, tokens);
        }
        fclose(this->fin);
        FILE *clearFile = fopen(inp_file, "w");
        if (clearFile) fclose(clearFile);
        runASingleTrace(tokens, spec_and_serial, eval) ;
        tokens.clear() ;
        printf("--------------------------\n");
        printf("DEBUG: DONE WITH LINE\n"); 
        printf("--------------------------\n");
        fclose(this->fout);
        fclose(this->oracle_out);
        eval.reset_evaluator();
    }
    // if(this->areFilesOpened)fclose(this->fin) ; 
    if(this->areFilesOpened)fclose(this->fout) ;
    this->areFilesOpened = false ;  

}

void Fuzzer::replay_traces(char * inp_file, char* output_file, char* oracle_response_file)
{ 
    printf("parsing specification..\n");
    std::pair<TypeChecker, vector<int>> spec_and_serial = parse_spec("ltl-parser/specification.txt");
    printf("specification parsed!\n");
    Evaluator eval(root.second, spec_and_serial.second);
    printf("Evaluator created.\n");

    this->fin = fopen(inp_file, "r") ; 
    WarningMessages::PositiveConditionMsg(this->fin != NULL, "Couldn't open input file"); 
    this->fout = fopen(output_file, "a") ; 
    this->oracle_out = fopen(oracle_response_file, "w");
    WarningMessages::PositiveConditionMsg(this->fout != NULL, "Couldn't open output file") ; 
    WarningMessages::PositiveConditionMsg(this->isConnectStateAvailable, "There is no connection state"); 
    this->areFilesOpened = true ; 
    char line[100000] ; 
    size_t iter = 0 ; 
    while(fgets(line,sizeof(line),fin))
    {
        vector<string> tokens; 
        tokens.clear() ;
        tokenizeALine(line, tokens);
        runASingleTrace(tokens, spec_and_serial, eval) ;  
        ++iter ; 
        printf("--------------------------\n");
        printf("DEBUG: DONE WITH LINE %u\n",iter); 
        printf("--------------------------\n");
        eval.reset_evaluator();
    }
    if(this->areFilesOpened)fclose(this->fin) ; 
    if(this->areFilesOpened)fclose(this->fout) ;
    fclose(this->oracle_out);
    this->areFilesOpened = false ;  
}
