#pragma once
#include "types.h"
#include <vector>
using namespace std;

vector<SuspiciousCaller> runRuleEngine(const vector<CDRRecord>& records);