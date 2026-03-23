#pragma once
#include <string>
#include <vector>
using namespace std;

struct CDRRecord {
    string caller_id;
    string receiver_id;
    int    duration_sec;
    string timestamp;
};

struct BlacklistHit {
    string caller_id;
    string reason;
};

struct SuspiciousCaller {
    string         caller_id;
    double         suspicion_score;
    int            total_calls;
    double         avg_duration;
    int            unique_receivers;
    vector<string> violations;
};

struct FraudRing {
    int            ring_id;
    vector<string> members;
};