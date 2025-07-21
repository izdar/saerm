#include "predicate_transformer.h"

PredicateTransformer::PredicateTransformer() {
    group_id = send_confirm = ap_group = ap_send_confirm = prev_ap_group = prev_ap_send_confirm = -1;
    rg_container = ac_container = pi_container = ap_pi_container = ap_pi = ac = pi = false;
    parser_error_code = 1;
    request = messageNotSet;
    response = messageNotSet;
    our_status_code = statusNotSet;
    ap_status_code = statusNotSet;
    rg = supportNotSet;
}

void PredicateTransformer::readOCamlOracle() {
    std::ifstream file("../../WiFiPacketGen/sync/driver_oracle.json");
    if (!file.is_open()) {
        std::cerr << "Could not open the file!" << std::endl;
        return;
    }
    file >> this->oracle;
}

void PredicateTransformer::resetTransformer() {
    group_id = send_confirm = ap_group = ap_send_confirm = -1;
    rg_container = ac_container = pi_container = ap_pi_container = ap_pi = ac = pi = false;
    request = messageNotSet;
    response = messageNotSet;
    our_status_code = statusNotSet;
    ap_status_code = statusNotSet;
    rg = supportNotSet;
}

void PredicateTransformer::map_response_to_predicates(sae_response &ap_ctx, sae_frame_t &response_frame) {
    if (response_frame.type == COMMIT) {
        if (ap_ctx.status == 126) {
            ap_status_code = h2e;
            response = commit_success;
            ap_group = ap_ctx.group_id;
        } else if (ap_ctx.status == 0) {
            ap_status_code = success;
            response = commit_success;
            ap_group = ap_ctx.group_id;
        } else if (ap_ctx.status == 77) {
            ap_status_code = unsupported_cylic_group;
            ap_group = ap_ctx.group_id;
        } else if (ap_ctx.status == 76) {
            response = commit_ac_token;
        } else if (ap_ctx.status == 1) {
            response = commit_error;
            ap_status_code = unspecified_failure;
        } else if (ap_ctx.status == 0x7b) {
            ap_status_code = unknown_password_identifier;
            response = commit_error;
        }
    }
    else if (response_frame.type == TIMEOUT) {
        response = timeout;
    }
    else if (response_frame.type == CONFIRM) {
        if (ap_ctx.status == 0) {
            response = confirm_success;
        } else {
            response = confirm_error;
        }
        ap_send_confirm = htole16(ap_ctx.send_confirm);
    } else if (response_frame.type == ASSOC_RESPONSE) {
        response = association_response;
    }
}

void PredicateTransformer::map_request_to_predicates(packet_type pkt, sae_context &sae_ctx, fuzzer_frame_t &frame) {
    if (pkt == COMMIT) {
        request = commit_success;
        our_status_code = h2e;
        group_id = 19;
    } else if (pkt == CONFIRM) {
        request = confirm_success;
        our_status_code = success;
        send_confirm = htole16(sae_ctx.send_confirm);
    } else if (pkt == ASSOCIATION_REQ) {
        request = association_request;
    }
    else {
        // if (oracle.contains("failed")) {
        //     request = unknown;
        // }
        if (oracle.contains("algo")) {
            if (oracle.contains("auth_seq")) {
                if (oracle["auth_seq"] == "1") {
                    bool valid_commit = false;
                    if (oracle.contains("scalar")) {
                        if (oracle["scalar"] == "3c5343414c41523e") {
                            valid_commit = true;
                        } 
                    }
                    if (oracle.contains("element") && valid_commit) {
                        if (oracle["element"] == "3c53454e445f434f4e4649524d3e") {
                            valid_commit = true;
                        }
                    }
                    if (oracle.contains("rg_list")) {
                        rg_container = true;
                        for (int i = 0; i < frame.rejected_groups_len; i += 2) {
                            uint16_t rg_group_id;
                            
                            if (i + 1 < frame.rejected_groups_len) {
                                // Normal case: two bytes available for a complete uint16_t
                                // Convert from big endian to little endian
                                rg_group_id = (frame.rejected_groups[i + 1] << 8) | frame.rejected_groups[i];
                            } else {
                                // Handle odd length: only one byte left, place it in the low byte
                                // High byte becomes 0
                                rg_group_id = frame.rejected_groups[i];
                            }
                            printf("----RG_FOUND----\n\t%d\n-----------\n", rg_group_id);
                            if (rg_group_id == 19 || rg_group_id == 20 || rg_group_id == 21) {
                                printf("----SET SUPPORTED-----------\n");
                                rg = supported;
                                break;
                            }
                        }
                        
                        rg = rg == supported ? rg : unsupported;
                    }
                    if (oracle.contains("pi_list")) {
                        pi_container = true;
                        if (frame.password_id) {
                            pi = true;
                        }
                    }
                    if (oracle.contains("ac_list")) {
                        ac_container = true;
                        if (frame.ac_token_container) {
                            ac = true;
                        }
                    }
                    if (oracle.contains("ac_token")) {
                        if (oracle["ac_token"] == "3c41435f544f4b454e3e") {
                            ac = true;
                        }
                    }
                    if (valid_commit && oracle["algo"] == "3" && (oracle["status"] == "0" || oracle["status"] == "126")) {
                        request = commit_success;
                    } else if (oracle["status"] == 1 && oracle["algo"] == "3") {
                        request = commit_error;
                    } else if (valid_commit && oracle["algo"] == "3" && !(oracle["status"] == "0" || oracle["status"] == "126")) {
                        request = commit_bad;
                    } else if (oracle["algo"] != "3") {
                        request = unknown;
                    }
                } else if (oracle["auth_seq"] == "2") {
                    bool valid_confirm = false;
                    if (oracle.contains("confirm_hash")) {
                        if (oracle["confirm_hash"] == "3c636f6e6669726d5f686173683e") {
                            valid_confirm = true;
                        }
                    }
                    if (oracle.contains("send_confirm") && valid_confirm) {
                        if (oracle["send_confirm"] == "3c53454e445f434f4e4649524d5f434f554e5445523e") {
                            valid_confirm = true;
                        }
                        send_confirm = htole16(sae_ctx.send_confirm);
                    }
                    if (oracle["status"] != "0") valid_confirm = false;
                    if (valid_confirm) request = confirm_success; else request = confirm_bad;
                } else {
                    request = unknown;
                }
                if (oracle["status"] == "126") our_status_code = h2e;
                else if (oracle["status"] == "0") our_status_code = success;
                else if (oracle["status"] == "1") our_status_code = unspecified_failure;
                else if (oracle["status"] == "77") our_status_code = unsupported_cylic_group;
                else if (oracle["status"] == "123") our_status_code = unknown_password_identifier;
            }
        }
    }
    // if (pkt == COMMIT) {
    //     request = commit_success;
    //     our_status_code = h2e;
    //     group_id = 19;
    // } else if (pkt == CONFIRM) {
    //     request = confirm_success;
    // } else if (pkt == ASSOCIATION_REQ) {
    //     request = association_request;
    // } else {
    //     if (frame.algo != 3) {
    //         request = unknown;
    //     } else {
    //         if (frame.seq == 1) {
    //             if (frame.status_code == 126) {
    //                 our_status_code = h2e;
    //             } else if (frame.status_code == 0) {
    //                 our_status_code = success;
    //             } else if (frame.status_code == 77) {
    //                 our_status_code = unsupported_cylic_group;
    //             } else if (frame.status_code == 0x7b) {
    //                 our_status_code = unknown_password_identifier;
    //             } else request = commit_bad;
    //             group_id = frame.group_id;
    //             if (frame.scalar_is_placeholder && frame.element_is_placeholder)
    //                 { if (request != unknown && parser_error_code >= 0) request = commit_success; } else request = commit_bad;
    //             if (frame.rejected_groups_present) {
    //                 rg_container = true;
    //                 for (int i = 0; i < frame.rejected_groups_len; ++i) {
    //                     if (frame.rejected_groups[i] == 19 || frame.rejected_groups[i] == 20 || frame.rejected_groups[i] == 21) {
    //                         rg = supported;
    //                     }
    //                 }
    //                 if (rg != supported) rg = unsupported; 
    //             }
    //             if (frame.password_id_present) {
    //                 pi_container = true;
    //                 if (frame.password_id) {
    //                     pi = true;
    //                 }
    //             }
    //             if (frame.ac_token_container_present) {
    //                 ac_container = true;
    //                 if (frame.ac_token_container) {
    //                     ac = true;
    //                 }
    //             }
    //         } else if (frame.seq == 2) {
    //             if (frame.status_code == 0 && frame.send_confirm_is_placeholder && frame.confirm_hash_is_placeholder) {
    //                 request = confirm_success;
    //                 send_confirm = sae_ctx.send_confirm;
    //             } else { request = confirm_bad; }
    //         } else request = unknown;
    //     }
    // }
}

std::string PredicateTransformer::write_to_file() {
    std::string out;

    out += "group=" + std::to_string(group_id) + " ";
    out += "ap_group=" + std::to_string(ap_group) + " ";
    out += "send_confirm=" + std::to_string(send_confirm) + " ";
    out += "ap_send_confirm=" + std::to_string(ap_send_confirm) + " ";
    out += "prev_ap_group=" + std::to_string(prev_ap_group) + " ";
    out += "prev_ap_send_confirm=" + std::to_string(prev_ap_send_confirm) + " ";
    

    out += "rg_container=" + std::string(rg_container ? "true" : "false") + " ";
    out += "ac_container=" + std::string(ac_container ? "true" : "false") + " ";
    out += "pi_container=" + std::string(pi_container ? "true" : "false") + " ";
    out += "pi=" + std::string(pi ? "true" : "false") + " ";

    switch (request) {
        case commit_success: out += "request=client_commit_success "; break;
        case commit_bad: out += "request=client_commit_bad "; break;
        case association_request: out += "request=association_request "; break;
        case unknown: out += "request=unknown "; break;
        case commit_error: out += "request=client_commit_error "; break;
        case confirm_success: out += "request=client_confirm_success "; break;
        case confirm_bad: out += "request=client_confirm_bad "; break;
        case commit_success_ac_token: out += "request=client_commit_success_ac_token "; break;
        default: out += "request=requestNotSet "; break;
    }

    switch (our_status_code) {
        case success: out += "client_status_code=0 "; break;
        case h2e: out += "client_status_code=126 "; break;
        case unsupported_cylic_group: out += "client_status_code=77 "; break;
        case unknown_password_identifier: out += "client_status_code=123 "; break;
        case unspecified_failure: out += "client_status_code=1 "; break;
        default: out += "client_status_code=-1 "; break;
    }

    switch (rg) {
        case supported: out += "support=supported "; break;
        case unsupported: out += "support=unsupported "; break;
        default: out += "support=supportNotSet "; break;
    }

    switch (response) {
        case timeout: out += "response=timeout "; break;
        case commit_success: out += "response=ap_commit_success "; break;
        case commit_bad: out += "response=ap_commit_bad "; break;
        case association_response: out += "response=association_response "; break;
        case commit_error: out += "response=ap_commit_error "; break;
        case confirm_success: out += "response=ap_confirm_success "; break;
        case confirm_bad: out += "response=ap_confirm_bad "; break;
        case commit_ac_token: out += "response=ap_commit_success_ac_token "; break;
        default: out += "response=responseNotSet "; break;
    }

    switch (ap_status_code) {
        case success: out += "ap_status_code=0 "; break;
        case h2e: out += "ap_status_code=126 "; break;
        case unsupported_cylic_group: out += "ap_status_code=77 "; break;
        case unknown_password_identifier: out += "ap_status_code=123 "; break;
        case unspecified_failure: out += "ap_status_code=1 "; break;
        default: out += "ap_status_code=-1 ";break;
    }

    return out;
}

void PredicateTransformer::read_predicates(std::string &input, State &state) {
    char buffer[2048];
    strncpy(buffer, input.c_str(), sizeof(buffer));
    buffer[sizeof(buffer) - 1] = '\0';  // Ensure null-termination

    char* token = strtok(buffer, " ");
    while (token != nullptr) {
        char* equal_sign = strchr(token, '=');
        if (equal_sign) {
            *equal_sign = '\0';
            const char* key = token;
            const char* value = equal_sign + 1;
            state.addLabel(key, value);
            printf("Key: %s, Value: %s\n", key, value);
        }
        token = strtok(nullptr, " ");
    }
}

void PredicateTransformer::predicate_transform(packet_type pkt_type, sae_context &sae_ctx, sae_response &ap_ctx, fuzzer_frame_t &frame, sae_frame_t &response_frame, State &state, int prev_ap_group_, int prev_ap_send_confirm_, int err) {
    this->prev_ap_group = prev_ap_group_;
    this->prev_ap_send_confirm = prev_ap_send_confirm_;
    this->parser_error_code = err;
    readOCamlOracle();
    map_response_to_predicates(ap_ctx, response_frame);
    map_request_to_predicates(pkt_type, sae_ctx, frame);
    std::string predicate_string = write_to_file();
    read_predicates(predicate_string, state);
    state.IsSane();
    resetTransformer();
}