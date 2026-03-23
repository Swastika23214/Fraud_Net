
#include "../include/m4_graph.h"
#include <unordered_map>
#include <unordered_set>
#include <queue>
#include <algorithm>
#include <iostream>
using namespace std;

class CallGraph {
    unordered_map<string, unordered_set<string>> adj;       
    unordered_map<string, unordered_set<string>> undirected;

public:
    void build(const vector<CDRRecord>& records) {
        for (const auto& r : records) {
            adj[r.caller_id].insert(r.receiver_id);
            if (!adj.count(r.receiver_id)) adj[r.receiver_id] = {};
            undirected[r.caller_id].insert(r.receiver_id);
            undirected[r.receiver_id].insert(r.caller_id);
        }
    }

    int nodeCount() { return (int)adj.size(); }
    int edgeCount() {
        int e = 0;
        for (auto& [n, nb] : adj) e += (int)nb.size();
        return e;
    }

   
    bool dfsCycle(const string& node,
                  unordered_map<string, int>& color,
                  vector<string>& path) {
        color[node] = 1; // GRAY
        path.push_back(node);
        for (const auto& nb : adj[node]) {
            if (color[nb] == 1) {
                // Back edge found — extract cycle
                auto it = find(path.begin(), path.end(), nb);
                path = vector<string>(it, path.end());
                path.push_back(nb); // close the loop
                return true;
            }
            if (color[nb] == 0 && dfsCycle(nb, color, path))
                return true;
        }
        path.pop_back();
        color[node] = 2; // BLACK
        return false;
    }

    vector<FraudRing> findFraudRings() {
        unordered_map<string, int> color;
        for (auto& [n, _] : adj) color[n] = 0;

        vector<FraudRing> rings;
        int id = 1;

        for (auto& [node, _] : adj) {
            if (color[node] == 0) {
                vector<string> path;
                if (dfsCycle(node, color, path)) {
                    // Dedup by member set
                    unordered_set<string> pset(path.begin(), path.end());
                    bool dup = false;
                    for (auto& r : rings) {
                        unordered_set<string> eset(r.members.begin(), r.members.end());
                        if (pset == eset) { dup = true; break; }
                    }
                    if (!dup && path.size() > 2)  
                        rings.push_back({id++, path});
                }
            }
        }
        return rings;
    }

    vector<vector<string>> findComponents() {
        unordered_set<string> visited;
        vector<vector<string>> components;
        for (auto& [node, _] : undirected) {
            if (!visited.count(node)) {
                vector<string> comp;
                queue<string> q;
                q.push(node); visited.insert(node);
                while (!q.empty()) {
                    string curr = q.front(); q.pop();
                    comp.push_back(curr);
                    for (const auto& nb : undirected[curr])
                        if (!visited.count(nb)) { visited.insert(nb); q.push(nb); }
                }
                components.push_back(comp);
            }
        }
        sort(components.begin(), components.end(), [](const vector<string>& a, const vector<string>& b) {
            return a.size() > b.size();
        });
        return components;
    }
};

vector<FraudRing> detectFraudRings(const vector<CDRRecord>& records) {
    CallGraph graph;
    graph.build(records);

    cout << "[M4] Graph nodes : " << graph.nodeCount() << "\n";
    cout << "[M4] Graph edges : " << graph.edgeCount() << "\n";

    auto rings = graph.findFraudRings();
    cout << "[M4] Fraud rings : " << rings.size() << "\n";

    return rings;
}