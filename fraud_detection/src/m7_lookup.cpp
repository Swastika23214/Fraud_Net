
#include "../include/m7_lookup.h"
#include <sqlite3.h>
#include <unordered_set>
#include <iostream>
using namespace std;

struct TrieNode {
    TrieNode* ch[10];
    bool      isEnd;
    string    label;
    TrieNode() : isEnd(false), label("") {
        for (int i = 0; i < 10; i++) ch[i] = nullptr;
    }
};

class LookupTrie {
    TrieNode* root;
    void destroy(TrieNode* n) {
        if (!n) return;
        for (int i = 0; i < 10; i++) destroy(n->ch[i]);
        delete n;
    }
public:
    LookupTrie()  { root = new TrieNode(); }
    ~LookupTrie() { destroy(root); }

    void insert(const string& prefix, const string& label) {
        TrieNode* curr = root;
        for (char c : prefix) {
            int i = c - '0';
            if (!curr->ch[i]) curr->ch[i] = new TrieNode();
            curr = curr->ch[i];
        }
        curr->isEnd = true;
        curr->label = label;
    }

    pair<bool, string> match(const string& number) {
        TrieNode* curr = root;
        for (char c : number) {
            int i = c - '0';
            if (!curr->ch[i]) break;
            curr = curr->ch[i];
            if (curr->isEnd) return {true, curr->label};
        }
        return {false, ""};
    }
};

static LookupTrie* getPrefixTrie() {
    static LookupTrie* trie = nullptr;
    if (!trie) {
        trie = new LookupTrie();
        trie->insert("9696", "Wangiri suspect range");
        trie->insert("9800", "Robocall suspect range");
        trie->insert("9111", "Fraud ring range A");
        trie->insert("9222", "Fraud ring range B");
        trie->insert("9000", "Reported spam range");
        trie->insert("9999", "Reported fraud range");
    }
    return trie;
}

static unordered_set<string>& getBlacklist() {
    static unordered_set<string> bl = {"9876543210", "9123456789"};
    return bl;
}

LookupResult lookupNumber(const string& number) {
    LookupResult res;
    res.number          = number;
    res.is_blacklisted  = false;
    res.is_suspicious   = false;
    res.suspicion_score = 0;
    res.total_calls     = 0;
    res.avg_duration    = 0;
    res.unique_receivers= 0;
    res.in_fraud_ring   = false;
    res.ring_id         = -1;
    res.found_in_dataset= false;

    if (getBlacklist().count(number)) {
        res.is_blacklisted = true;
        res.prefix_match   = "EXACT BLACKLIST MATCH";
    }

    if (!res.is_blacklisted) {
        auto [hit, label] = getPrefixTrie()->match(number);
        if (hit) res.prefix_match = label;
    }

    sqlite3* db;
    if (sqlite3_open("fraud_detection.db", &db) == SQLITE_OK) {

        string sql0 = "SELECT COUNT(*) FROM cdr_records WHERE caller_id = '"
                      + number + "' OR receiver_id = '" + number + "' LIMIT 1;";
        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db, sql0.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW)
                res.found_in_dataset = sqlite3_column_int(stmt, 0) > 0;
            sqlite3_finalize(stmt);
        }
        string sql1 = "SELECT suspicion_score, total_calls, avg_duration, "
                      "unique_receivers, violations FROM suspicious_callers "
                      "WHERE caller_id = '" + number + "' LIMIT 1;";
        if (sqlite3_prepare_v2(db, sql1.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                res.is_suspicious    = true;
                res.suspicion_score  = sqlite3_column_double(stmt, 0);
                res.total_calls      = sqlite3_column_int(stmt, 1);
                res.avg_duration     = sqlite3_column_double(stmt, 2);
                res.unique_receivers = sqlite3_column_int(stmt, 3);
                res.violations       = string((char*)sqlite3_column_text(stmt, 4));
            }
            sqlite3_finalize(stmt);
        }

        string sql2 = "SELECT ring_id, members FROM fraud_rings "
                      "WHERE members LIKE '%" + number + "%' LIMIT 1;";
        if (sqlite3_prepare_v2(db, sql2.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
            if (sqlite3_step(stmt) == SQLITE_ROW) {
                res.in_fraud_ring = true;
                res.ring_id       = sqlite3_column_int(stmt, 0);
                res.ring_members  = string((char*)sqlite3_column_text(stmt, 1));
            }
            sqlite3_finalize(stmt);
        }

        sqlite3_close(db);
    } else {
        cerr << "[M7] Could not open DB — run main pipeline first\n";
    }

    if (!res.found_in_dataset && !res.is_blacklisted && res.prefix_match.empty())
        res.verdict = "NOT_FOUND";
    else if (res.is_blacklisted || (res.is_suspicious && res.in_fraud_ring))
        res.verdict = "DANGEROUS";
    else if (res.is_suspicious || res.in_fraud_ring || !res.prefix_match.empty())
        res.verdict = "SUSPICIOUS";
    else
        res.verdict = "CLEAN";

    return res;
}

void printLookupResult(const LookupResult& r) {
    cout << "\n[M7] Lookup: " << r.number << "\n";
    cout << "--------------------------------------\n";
    cout << "Verdict          : " << r.verdict << "\n";
    cout << "Blacklisted      : " << (r.is_blacklisted ? "YES" : "No") << "\n";
    cout << "Prefix match     : " << (r.prefix_match.empty() ? "None" : r.prefix_match) << "\n";
    cout << "Suspicious (M3)  : " << (r.is_suspicious ? "YES" : "No");
    if (r.is_suspicious) {
        cout << "  score=" << r.suspicion_score
             << "  calls=" << r.total_calls
             << "  avgDur=" << r.avg_duration << "s"
             << "  uniqueRecv=" << r.unique_receivers
             << "\n  Violations: " << r.violations;
    }
    cout << "\n";
    cout << "In fraud ring    : " << (r.in_fraud_ring ? "YES — Ring #" + to_string(r.ring_id) : "No") << "\n";
    if (r.in_fraud_ring)
        cout << "Ring members     : " << r.ring_members << "\n";
    cout << "--------------------------------------\n";
}