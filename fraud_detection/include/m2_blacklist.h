#pragma once
#include "types.h"
#include <string>
#include <vector>
using namespace std;

vector<BlacklistHit> runBlacklistScan(const vector<CDRRecord>& records);