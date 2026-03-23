
#include "../include/m3_rules.h"
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <iostream>
#include <ctime>
using namespace std;

const int    FREQ_THRESHOLD     = 50;
const int    DURATION_THRESHOLD = 10;
const int    UNIQUE_THRESHOLD   = 30;
const int    BURST_CALLS        = 20;
const int    BURST_HOURS        = 2;
const double SCORE_PER_RULE     = 25.0;

struct CallerStats {
    string                caller_id;
    int                   total_calls    = 0;
    long long             total_duration = 0;
    unordered_set<string> unique_receivers;
    vector<string>        timestamps;
};

static time_t parseTs(const string& ts) {
    struct tm t = {};
    sscanf(ts.c_str(), "%d-%d-%d %d:%d:%d",
        &t.tm_year, &t.tm_mon, &t.tm_mday,
        &t.tm_hour, &t.tm_min, &t.tm_sec);
    t.tm_year -= 1900; t.tm_mon -= 1; t.tm_isdst = -1;
    return mktime(&t);
}

class IRule {
public:
    virtual bool   evaluate(const CallerStats& s) = 0;
    virtual string name() = 0;
    virtual ~IRule() {}
};


class FrequencyRule : public IRule {
public:
    bool evaluate(const CallerStats& s) override {
        return s.total_calls > FREQ_THRESHOLD;
    }
    string name() override { return "HIGH_FREQUENCY"; }
};

class ShortDurationRule : public IRule {
public:
    bool evaluate(const CallerStats& s) override {
        if (!s.total_calls) return false;
        return (double)s.total_duration / s.total_calls < DURATION_THRESHOLD;
    }
    string name() override { return "SHORT_DURATION"; }
};


class UniqueReceiverRule : public IRule {
public:
    bool evaluate(const CallerStats& s) override {
        return (int)s.unique_receivers.size() > UNIQUE_THRESHOLD;
    }
    string name() override { return "MANY_UNIQUE_RECEIVERS"; }
};

class BurstRule : public IRule {
public:
    bool evaluate(const CallerStats& s) override {
        if ((int)s.timestamps.size() < BURST_CALLS) return false;
        vector<time_t> times;
        for (const auto& ts : s.timestamps)
            times.push_back(parseTs(ts));
        sort(times.begin(), times.end());
        int left = 0, maxW = 0;
        for (int right = 0; right < (int)times.size(); right++) {
            while (times[right] - times[left] > BURST_HOURS * 3600) left++;
            maxW = max(maxW, right - left + 1);
        }
        return maxW >= BURST_CALLS;
    }
    string name() override { return "BURST_DETECTED"; }
};


vector<SuspiciousCaller> runRuleEngine(const vector<CDRRecord>& records) {
    unordered_map<string, CallerStats> statsMap;

    for (const auto& r : records) {
        auto& s = statsMap[r.caller_id];
        s.caller_id = r.caller_id;
        s.total_calls++;
        s.total_duration += r.duration_sec;
        s.unique_receivers.insert(r.receiver_id);
        s.timestamps.push_back(r.timestamp);
    }

    vector<IRule*> rules = {
        new FrequencyRule(),
        new ShortDurationRule(),
        new UniqueReceiverRule(),
        new BurstRule()
    };

    vector<SuspiciousCaller> flagged;

    for (auto& [id, stats] : statsMap) {
        double score = 0;
        vector<string> violations;
        for (auto* rule : rules) {
            if (rule->evaluate(stats)) {
                score += SCORE_PER_RULE;
                violations.push_back(rule->name());
            }
        }
        if (score > 0) {
            double avg = (double)stats.total_duration / stats.total_calls;
            flagged.push_back({
                id, score,
                stats.total_calls, avg,
                (int)stats.unique_receivers.size(),
                violations
            });
        }
    }

    for (auto* r : rules) delete r;

    sort(flagged.begin(), flagged.end(), [](const SuspiciousCaller& a, const SuspiciousCaller& b) {
        return a.suspicion_score > b.suspicion_score;
    });

    cout << "[M3] Suspicious callers: " << flagged.size() << "\n";
    return flagged;
}