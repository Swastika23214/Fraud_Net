#pragma once
#include <string>
using namespace std;

struct LookupResult {
    string number;
    bool   is_blacklisted;
    string prefix_match;       
    bool   is_suspicious;
    double suspicion_score;
    int    total_calls;
    double avg_duration;
    int    unique_receivers;
    string violations;         
    bool   in_fraud_ring;
    int    ring_id;
    string ring_members;      
    bool   found_in_dataset;   
    string verdict;            
};

LookupResult lookupNumber(const string& number);