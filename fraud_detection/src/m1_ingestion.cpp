#include "../include/m1_ingestion.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
using namespace std;

static string trim(const string& s) {
    int start = 0, end = (int)s.size() - 1;
    while (start <= end && (s[start]==' '||s[start]=='\r'||s[start]=='\n')) start++;
    while (end >= start && (s[end]  ==' '||s[end]  =='\r'||s[end]  =='\n')) end--;
    return s.substr(start, end - start + 1);
}

static bool parseLine(const string& line, CDRRecord& rec) {
    stringstream ss(line);
    string tok;
    vector<string> f;
    while (getline(ss, tok, ',')) f.push_back(trim(tok));
    if (f.size() < 4) return false;
    rec.caller_id   = f[0];
    rec.receiver_id = f[1];
    rec.timestamp   = f[3];
    try {
        rec.duration_sec = stoi(f[2]);
        if (rec.duration_sec < 0) return false;
    } catch (...) { return false; }
    if (rec.caller_id.size() != 10 || rec.receiver_id.size() != 10) return false;
    if (rec.caller_id == rec.receiver_id) return false;
    return true;
}

vector<CDRRecord> loadCDR(const string& filepath) {
    vector<CDRRecord> records;
    ifstream file(filepath);
    if (!file.is_open()) throw runtime_error("[M1] Cannot open: " + filepath);
    string line;
    int lineNum = 0, skipped = 0;
    getline(file, line); // skip header
    while (getline(file, line)) {
        lineNum++;
        if (trim(line).empty()) continue;
        CDRRecord rec;
        if (parseLine(line, rec)) records.push_back(rec);
        else { skipped++; cerr << "[M1] Bad record line " << lineNum << "\n"; }
    }
    file.close();
    cout << "[M1] Loaded : " << records.size() << " records ("
         << skipped << " skipped)\n";
    return records;
}