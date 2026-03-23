// ============================================================
// MAIN — Fraud Detection Pipeline + HTTP Server
//
// Flow:
//   1. Load CDR from data/cdr_input.csv          (M1)
//   2. Blacklist & prefix scan                   (M2)
//   3. Greedy behavioral rule engine             (M3)
//   4. Graph construction & fraud ring detection (M4)
//   5. Merge sort ranking                        (M5)
//   6. Persist all results to SQLite             (M6)
//   7. Serve JSON endpoints for frontend         (HTTP)
//
// Compile:
//   g++ -std=c++17 -o fraud_detector \
//       src/main.cpp src/m1_ingestion.cpp src/m2_blacklist.cpp \
//       src/m3_rules.cpp src/m4_graph.cpp src/m5_sorting.cpp \
//       src/m6_database.cpp \
//       -Iinclude -lsqlite3
//
// Run:
//   ./fraud_detector
//   Then open frontend/index.html in your browser
// ============================================================

#include "m1_ingestion.h"
#include "m2_blacklist.h"
#include "m3_rules.h"
#include "m4_graph.h"
#include "m5_sorting.h"
#include "m6_database.h"
#include "m7_lookup.h"

// cpp-httplib (single header — place httplib.h in include/)
#include "httplib.h"

#include <iostream>
#include <string>
using namespace std;

int main() {
    cout << "========================================================\n";
    cout << "   FRAUD DETECTION SYSTEM\n";
    cout << "========================================================\n\n";

    // ── M6: Init database ─────────────────────────────────────
    dbInit();

    // ── M1: Load CDR dataset ──────────────────────────────────
    vector<CDRRecord> records;
    try {
        records = loadCDR("data/cdr_input.csv");
    } catch (const exception& e) {
        cerr << "[ERROR] " << e.what() << "\n";
        return 1;
    }
    dbStoreCDR(records);

    // ── M2: Blacklist scan ────────────────────────────────────
    cout << "\n[Pipeline] Running M2: Blacklist scan...\n";
    auto blacklistHits = runBlacklistScan(records);
    dbStoreBlacklistHits(blacklistHits);

    // ── M3: Rule engine ───────────────────────────────────────
    cout << "\n[Pipeline] Running M3: Rule engine...\n";
    auto suspicious = runRuleEngine(records);

    // ── M5: Sort/rank ─────────────────────────────────────────
    cout << "\n[Pipeline] Running M5: Ranking...\n";
    suspicious = rankCallers(suspicious);
    dbStoreSuspiciousCallers(suspicious);

    // ── M4: Fraud ring detection ──────────────────────────────
    cout << "\n[Pipeline] Running M4: Fraud ring detection...\n";
    auto rings = detectFraudRings(records);
    dbStoreFraudRings(rings);

    // ── Summary ───────────────────────────────────────────────
    cout << "\n========================================================\n";
    cout << "   RESULTS\n";
    cout << "========================================================\n";
    cout << "CDR records analysed : " << records.size()       << "\n";
    cout << "Blacklist hits       : " << blacklistHits.size() << "\n";
    cout << "Suspicious callers   : " << suspicious.size()    << "\n";
    cout << "Fraud rings detected : " << rings.size()         << "\n";
    cout << "========================================================\n";

    // ── HTTP Server ───────────────────────────────────────────
    httplib::Server svr;

    // CORS headers for all responses
    auto cors = [](httplib::Response& res) {
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Headers", "Content-Type");
    };

    svr.Get("/api/summary", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dbGetSummaryJSON(), "application/json");
        cors(res);
    });

    svr.Get("/api/suspicious", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dbGetSuspiciousJSON(), "application/json");
        cors(res);
    });

    svr.Get("/api/fraud-rings", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dbGetFraudRingsJSON(), "application/json");
        cors(res);
    });

    svr.Get("/api/cdr-sample", [&](const httplib::Request&, httplib::Response& res) {
        res.set_content(dbGetCDRSampleJSON(20), "application/json");
        cors(res);
    });

    // M7: Single number lookup
    svr.Get("/api/lookup", [&](const httplib::Request& req, httplib::Response& res) {
        string number = req.get_param_value("number");
        if (number.empty() || number.size() != 10) {
            res.set_content("{\"error\":\"Provide a 10-digit number\"}", "application/json");
            cors(res);
            return;
        }
        LookupResult r = lookupNumber(number);
        string json = "{";
        json += "\"found_in_dataset\":"  + string(r.found_in_dataset?"true":"false") + ",";
        json += "\"number\":\""          + r.number                            + "\",";
        json += "\"verdict\":\""         + r.verdict                           + "\",";
        json += "\"is_blacklisted\":"    + string(r.is_blacklisted?"true":"false") + ",";
        json += "\"prefix_match\":\""    + r.prefix_match                      + "\",";
        json += "\"is_suspicious\":"     + string(r.is_suspicious?"true":"false")  + ",";
        json += "\"suspicion_score\":"   + to_string(r.suspicion_score)        + ",";
        json += "\"total_calls\":"       + to_string(r.total_calls)            + ",";
        json += "\"avg_duration\":"      + to_string(r.avg_duration)           + ",";
        json += "\"unique_receivers\":"  + to_string(r.unique_receivers)       + ",";
        json += "\"violations\":\""      + r.violations                        + "\",";
        json += "\"in_fraud_ring\":"     + string(r.in_fraud_ring?"true":"false")   + ",";
        json += "\"ring_id\":"           + to_string(r.ring_id)                + ",";
        json += "\"ring_members\":\""    + r.ring_members                      + "\"";
        json += "}";
        res.set_content(json, "application/json");
        cors(res);
    });

    // Serve frontend static files
    svr.set_mount_point("/", "./frontend");

    cout << "\n[Server] Running at http://localhost:8080\n";
    cout << "[Server] Open frontend/index.html in your browser\n";
    cout << "[Server] Press Ctrl+C to stop\n\n";

    svr.listen("0.0.0.0", 8080);
    return 0;
}