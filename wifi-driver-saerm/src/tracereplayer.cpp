# include "tracereplayer.h"

TraceReplayer::TraceReplayer()
{
    this->isConnectStateAvailable = false ; 
    this->areFilesOpened = false ; 
    this->fin = this->fout = NULL ; 
}

void TraceReplayer::setConnectionState(connectState * cinput)
{
    WarningMessages::PositiveConditionMsg(cinput != NULL, "The input connection you are giving me is NULL"); 
    this->cstate = cinput ; 
    this->isConnectStateAvailable = true ; 
    this->initializePWE(NULL) ; 
}

packet_type TraceReplayer::classifyToken( string &raw_token)
{
    if(raw_token == "COMMIT") return COMMIT ; 
    else if(raw_token == "CONFIRM") return CONFIRM ; 
    else if(raw_token=="ASSOCIATION_REQUEST") return ASSOCIATION_REQ ; 
    return RAW ; 
}

void TraceReplayer::printBinInHexInFile
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
    
    AP_CTX.ac_token = (unsigned char*) malloc(35 * sizeof(unsigned char)) ; 
    AP_CTX.group = group;
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

void FUZZER_FRAME_T_FREE(fuzzer_frame_t& frame) {
    if(frame.ac_token) free(frame.ac_token);
    if(frame.scalar) free(frame.scalar);
    if(frame.element) free(frame.element);
    if(frame.password_id) free(frame.password_id);
    if(frame.rejected_groups) free(frame.rejected_groups);
    if(frame.ac_token_container) free(frame.ac_token_container);
    if(frame.send_confirm) free(frame.send_confirm);
    if(frame.confirm_hash) free(frame.confirm_hash);
    if(frame.nonce) free(frame.nonce);
    if(frame.counter) free(frame.counter);
    if(frame.mic) free(frame.mic);
    if(frame.rsn_ie) free(frame.rsn_ie);
    if(frame.gtk) free(frame.gtk);
    if(frame.install_key_flag) free(frame.install_key_flag);
    if(frame.secure_bit) free(frame.secure_bit);
}

void TraceReplayer::runASingleTrace(vector<string>& trace)
{
    sae_context sae_ctx ;
    sae_response AP_ctx ; 
    sae_frame_t response ; 
    sae_replacements_t fieldReplacer ;
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    initialize_sae_context(group, (unsigned char *)cstate->getSSID().c_str(), cstate->destMAC, &sae_ctx) ; 
    AP_CTX_INITIALIZE(group, AP_ctx) ;
    
    // AP_ctx.scalar = BN_new() ;
    // AP_ctx.element = EC_POINT_new(sae_ctx.group);

    // Allocation happening here ... 
    FIELD_REPLACER_ALLOCATE(fieldReplacer) ; 

    for(int i = 0 ; i < trace.size(); ++i)
    {
          
        switch(classifyToken(trace[i])){
            case COMMIT : 
                SENDWRAPPER::COMMIT_MESSAGE(sae_ctx, cstate, response, pwe, AP_ctx); 
                if (response.data) {
                    free(response.data) ;
                    response.data = NULL;
                }
                WarningMessages::WarningWithoutCrashPositive(false, "we made it here after commit");
                break ; 
            case CONFIRM: 
                SENDWRAPPER::CONFIRM_MESSAGE(sae_ctx, AP_ctx, cstate, response, pwe) ; 
                if (response.data) {
                    free(response.data) ;
                    response.data = NULL;
                }
                break ; 
            case ASSOCIATION_REQ: 
                SENDWRAPPER::ASSOCIATION_MESSAGE(sae_ctx, AP_ctx, cstate, response); 
                if (response.data) {
                    free(response.data) ;
                    response.data = NULL;
                }
                break ; 
            case RAW: 
                fuzzer_frame_t  parsingHandler ; 
                SENDWRAPPER::RAW_PACKET(sae_ctx, AP_ctx, cstate, response, pwe, parsingHandler, fieldReplacer, trace[i]); 
                if (response.data) {
                    free(response.data) ;
                    response.data = NULL;
                }
                FUZZER_FRAME_T_FREE(parsingHandler);
                break ; 
            default: 
                WarningMessages::TerminatingErrorMessage("weird default case in runASingleTrace") ; break; 
        }
        if(response.data != NULL && response.data_len > 0)
            printBinInHexInFile(this->fout, response.data, response.data_len);
        else 
            fprintf(this->fout, "Received Nothing\n");

    }
    SENDWRAPPER::DEAUTH_MESSAGE(sae_ctx, cstate); //done sending a deauth message 
    //Deallocation will happen here 
    FIELD_REPLACER_FREE(fieldReplacer) ; 
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

void TraceReplayer::initializePWE(unsigned char *password_identifier){ 
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

void TraceReplayer::freePWE()
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

void TraceReplayer::runWholeFile(char * inp_file, char * output_file)
{ 
    this->fin = fopen(inp_file, "r") ; 
    WarningMessages::PositiveConditionMsg(this->fin != NULL, "Couldn't open input file"); 
    this->fout = fopen(output_file, "a") ; 
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
        runASingleTrace(tokens) ;  
        ++iter ; 
        printf("--------------------------\n");
        printf("DEBUG: DONE WITH LINE %u\n",iter); 
        printf("--------------------------\n");
    }
    if(this->areFilesOpened)fclose(this->fin) ; 
    if(this->areFilesOpened)fclose(this->fout) ;
    this->areFilesOpened = false ;  

}
