#ifndef PREDICATE_TRANSFORMER_H
#define PREDICATE_TRANSFORMER_H

extern "C" {
    #include "frame_structs.h"
    #include "driver.h"
    #include "oracle-parser.h"
}

#include "fuzzer.h"
#include "json.hpp"

enum message {messageNotSet, commit_success, commit_bad, timeout, commit_error, commit_reuse, unknown, confirm_error, commit_reflect, confirm_success, confirm_bad, association_request, association_response, commit_success_ac_token, commit_ac_token};
typedef enum message message_type;

enum status {statusNotSet, success, h2e, unsupported_cylic_group, unknown_password_identifier, unspecified_failure};
typedef enum status status_code;

// enum response {commit_success, commit_error, timeout, confirm_success, confirm_error, commit_ac_token, association_response};
// typedef enum response response_type;

enum support {supportNotSet, supported, unsupported};
typedef enum support rg_supported;

using json = nlohmann::json;

class PredicateTransformer {
public:
    
    int parser_error_code;
    int group_id;
    json oracle;
    int prev_ap_group;
    int prev_ap_send_confirm;
    int send_confirm;
    bool rg_container;
    bool ac_container;
    bool pi_container;
    bool ap_pi_container;
    bool ap_pi;
    bool ac;
    bool pi;
    int ap_group;
    int ap_send_confirm;
    message_type request;
    status_code our_status_code;
    status_code ap_status_code;
    message_type response;
    support rg;

    PredicateTransformer();
    void predicate_transform(packet_type pkt_type, sae_context &sae_ctx, sae_response &ap_ctx, fuzzer_frame_t &frame, sae_frame_t &response_frame, State &state, int prev_ap_group, int prev_ap_send_confirm, int err);
    void map_response_to_predicates(sae_response &ap_ctx, sae_frame_t &response);
    void map_request_to_predicates(packet_type pkt, sae_context &sae_ctx, fuzzer_frame_t &frame);
    std::string write_to_file();
    void resetTransformer();
    void readOCamlOracle();
    void read_predicates(std::string &, State &);
};

#endif