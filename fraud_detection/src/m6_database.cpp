
#include "../include/m6_database.h"
#include <sqlite3.h>
#include <iostream>
#include <sstream>
using namespace std;

static sqlite3* db = nullptr;

static void execSQL(const string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        cerr << "[M6] SQL error: " << err << "\n";
        sqlite3_free(err);
    }
}

static string esc(const string& s) {
    string out;
    for (char c : s) {
        if (c == '\'') out += "''";
        else out += c;
    }
    return out;
}

void dbInit() {
    if (sqlite3_open("fraud_detection.db", &db) != SQLITE_OK) {
        cerr << "[M6] Cannot open DB: " << sqlite3_errmsg(db) << "\n";
        return;
    }

    execSQL("PRAGMA journal_mode=WAL;");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS cdr_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id   TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            duration_sec INTEGER NOT NULL,
            timestamp   TEXT NOT NULL
        );
    )");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS blacklist_hits (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id TEXT NOT NULL,
            reason    TEXT NOT NULL
        );
    )");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS suspicious_callers (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            caller_id        TEXT NOT NULL,
            suspicion_score  REAL NOT NULL,
            total_calls      INTEGER NOT NULL,
            avg_duration     REAL NOT NULL,
            unique_receivers INTEGER NOT NULL,
            violations       TEXT NOT NULL
        );
    )");

    execSQL(R"(
        CREATE TABLE IF NOT EXISTS fraud_rings (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ring_id INTEGER NOT NULL,
            members TEXT NOT NULL,
            size    INTEGER NOT NULL
        );
    )");

    execSQL("DELETE FROM cdr_records;");
    execSQL("DELETE FROM blacklist_hits;");
    execSQL("DELETE FROM suspicious_callers;");
    execSQL("DELETE FROM fraud_rings;");

    cout << "[M6] Database initialised\n";
}

void dbStoreCDR(const vector<CDRRecord>& records) {
    execSQL("BEGIN TRANSACTION;");
    for (const auto& r : records) {
        string sql = "INSERT INTO cdr_records (caller_id, receiver_id, duration_sec, timestamp) VALUES ('"
            + esc(r.caller_id)   + "','"
            + esc(r.receiver_id) + "',"
            + to_string(r.duration_sec) + ",'"
            + esc(r.timestamp)   + "');";
        execSQL(sql);
    }
    execSQL("COMMIT;");
    cout << "[M6] Stored " << records.size() << " CDR records\n";
}

void dbStoreBlacklistHits(const vector<BlacklistHit>& hits) {
    execSQL("BEGIN TRANSACTION;");
    for (const auto& h : hits) {
        string sql = "INSERT INTO blacklist_hits (caller_id, reason) VALUES ('"
            + esc(h.caller_id) + "','" + esc(h.reason) + "');";
        execSQL(sql);
    }
    execSQL("COMMIT;");
    cout << "[M6] Stored " << hits.size() << " blacklist hits\n";
}

void dbStoreSuspiciousCallers(const vector<SuspiciousCaller>& callers) {
    execSQL("BEGIN TRANSACTION;");
    for (const auto& c : callers) {
        string viols;
        for (int i = 0; i < (int)c.violations.size(); i++) {
            viols += c.violations[i];
            if (i < (int)c.violations.size() - 1) viols += ", ";
        }
        string sql = "INSERT INTO suspicious_callers "
            "(caller_id, suspicion_score, total_calls, avg_duration, unique_receivers, violations) VALUES ('"
            + esc(c.caller_id) + "',"
            + to_string(c.suspicion_score) + ","
            + to_string(c.total_calls) + ","
            + to_string(c.avg_duration) + ","
            + to_string(c.unique_receivers) + ",'"
            + esc(viols) + "');";
        execSQL(sql);
    }
    execSQL("COMMIT;");
    cout << "[M6] Stored " << callers.size() << " suspicious callers\n";
}

void dbStoreFraudRings(const vector<FraudRing>& rings) {
    execSQL("BEGIN TRANSACTION;");
    for (const auto& ring : rings) {
        string members;
        for (int i = 0; i < (int)ring.members.size(); i++) {
            members += ring.members[i];
            if (i < (int)ring.members.size() - 1) members += " -> ";
        }
        string sql = "INSERT INTO fraud_rings (ring_id, members, size) VALUES ("
            + to_string(ring.ring_id) + ",'"
            + esc(members) + "',"
            + to_string((int)ring.members.size()) + ");";
        execSQL(sql);
    }
    execSQL("COMMIT;");
    cout << "[M6] Stored " << rings.size() << " fraud rings\n";
}

string dbGetSuspiciousJSON() {
    string json = "[";
    sqlite3_stmt* stmt;
    const char* sql = "SELECT caller_id, suspicion_score, total_calls, avg_duration, unique_receivers, violations "
                      "FROM suspicious_callers ORDER BY suspicion_score DESC;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json += ",";
            first = false;
            json += "{";
            json += "\"caller_id\":\""    + string((char*)sqlite3_column_text(stmt,0)) + "\",";
            json += "\"score\":"          + to_string(sqlite3_column_double(stmt,1))   + ",";
            json += "\"total_calls\":"    + to_string(sqlite3_column_int(stmt,2))      + ",";
            json += "\"avg_duration\":"   + to_string(sqlite3_column_double(stmt,3))   + ",";
            json += "\"unique_receivers\":"+ to_string(sqlite3_column_int(stmt,4))     + ",";
            json += "\"violations\":\""   + string((char*)sqlite3_column_text(stmt,5)) + "\"";
            json += "}";
        }
        sqlite3_finalize(stmt);
    }
    json += "]";
    return json;
}

string dbGetFraudRingsJSON() {
    string json = "[";
    sqlite3_stmt* stmt;
    const char* sql = "SELECT ring_id, members, size FROM fraud_rings ORDER BY ring_id;";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json += ",";
            first = false;
            json += "{";
            json += "\"ring_id\":"  + to_string(sqlite3_column_int(stmt,0))      + ",";
            json += "\"members\":\"" + string((char*)sqlite3_column_text(stmt,1)) + "\",";
            json += "\"size\":"     + to_string(sqlite3_column_int(stmt,2));
            json += "}";
        }
        sqlite3_finalize(stmt);
    }
    json += "]";
    return json;
}

string dbGetSummaryJSON() {
    ostringstream json;
    json << "{";

    sqlite3_stmt* stmt;

    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM cdr_records;", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    json << "\"total_records\":" << sqlite3_column_int(stmt, 0) << ",";
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM blacklist_hits;", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    json << "\"blacklist_hits\":" << sqlite3_column_int(stmt, 0) << ",";
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM suspicious_callers;", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    json << "\"suspicious_callers\":" << sqlite3_column_int(stmt, 0) << ",";
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM fraud_rings;", -1, &stmt, nullptr);
    sqlite3_step(stmt);
    json << "\"fraud_rings\":" << sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    json << "}";
    return json.str();
}


string dbGetCDRSampleJSON(int limit) {
    string json = "[";
    sqlite3_stmt* stmt;
    string sql = "SELECT caller_id, receiver_id, duration_sec, timestamp "
                 "FROM cdr_records LIMIT " + to_string(limit) + ";";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) == SQLITE_OK) {
        bool first = true;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            if (!first) json += ",";
            first = false;
            json += "{";
            json += "\"caller_id\":\""   + string((char*)sqlite3_column_text(stmt,0)) + "\",";
            json += "\"receiver_id\":\"" + string((char*)sqlite3_column_text(stmt,1)) + "\",";
            json += "\"duration\":"      + to_string(sqlite3_column_int(stmt,2))      + ",";
            json += "\"timestamp\":\""   + string((char*)sqlite3_column_text(stmt,3)) + "\"";
            json += "}";
        }
        sqlite3_finalize(stmt);
    }
    json += "]";
    return json;
}