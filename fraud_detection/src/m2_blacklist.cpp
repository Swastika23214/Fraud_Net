// ============================================================
// MODULE 2 — Blacklist & Prefix Detection
//
// Two-layer detection:
//   Layer 1 — Exact blacklist match : O(1) via unordered_set
//   Layer 2 — Prefix scam detection : O(k) via Trie
//             k = length of prefix checked
//
// Space Complexity: O(b + p*k)
//   b = blacklist entries, p = prefixes, k = avg prefix length
// ============================================================

#include "../include/m2_blacklist.h"
#include <unordered_set>
#include <iostream>
using namespace std;

// ── Trie ──────────────────────────────────────────────────────
struct TrieNode {
    TrieNode* ch[10];
    bool      isEnd;
    string    label;
    TrieNode() : isEnd(false), label("") {
        for (int i = 0; i < 10; i++) ch[i] = nullptr;
    }
};

class Trie {
    TrieNode* root;
    void destroy(TrieNode* n) {
        if (!n) return;
        for (int i = 0; i < 10; i++) destroy(n->ch[i]);
        delete n;
    }
public:
    Trie()  { root = new TrieNode(); }
    ~Trie() { destroy(root); }

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

class BlacklistChecker {
    unordered_set<string> bl;
    Trie trie;
public:
    void addNumber(const string& n)                       { bl.insert(n); }
    void addPrefix(const string& p, const string& label)  { trie.insert(p, label); }

    string check(const string& number) {
        if (bl.count(number)) return "BLACKLISTED";
        auto [hit, label] = trie.match(number);
        if (hit) return "SCAM_PREFIX: " + label;
        return "";
    }
};

vector<BlacklistHit> runBlacklistScan(const vector<CDRRecord>& records) {
    BlacklistChecker checker;

    checker.addPrefix("9696", "Wangiri suspect range");
    checker.addPrefix("9800", "Robocall suspect range");
    checker.addPrefix("9111", "Fraud ring range A");
    checker.addPrefix("9222", "Fraud ring range B");
    checker.addPrefix("9000", "Reported spam range");
    checker.addPrefix("9999", "Reported fraud range");

    checker.addNumber("9876543210");
    checker.addNumber("9123456789");

    vector<BlacklistHit> hits;
    unordered_set<string> seen;

    for (const auto& r : records) {
        if (!seen.count(r.caller_id)) {
            string reason = checker.check(r.caller_id);
            if (!reason.empty()) {
                hits.push_back({r.caller_id, reason});
                seen.insert(r.caller_id);
            }
        }
    }

    cout << "[M2] Blacklist/prefix hits: " << hits.size() << "\n";
    return hits;
}