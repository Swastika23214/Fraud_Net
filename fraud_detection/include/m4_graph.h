#pragma once
#include "types.h"
#include <vector>
using namespace std;

vector<FraudRing> detectFraudRings(const vector<CDRRecord>& records);