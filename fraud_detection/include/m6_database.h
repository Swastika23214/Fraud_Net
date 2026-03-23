#pragma once
#include "types.h"
#include <string>
#include <vector>
using namespace std;

void dbInit();
void dbStoreCDR(const vector<CDRRecord>& records);
void dbStoreBlacklistHits(const vector<BlacklistHit>& hits);
void dbStoreSuspiciousCallers(const vector<SuspiciousCaller>& callers);
void dbStoreFraudRings(const vector<FraudRing>& rings);

string dbGetSuspiciousJSON();
string dbGetFraudRingsJSON();
string dbGetSummaryJSON();
string dbGetCDRSampleJSON(int limit = 20);