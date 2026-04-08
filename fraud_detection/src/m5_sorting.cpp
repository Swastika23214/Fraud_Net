#include "../include/m5_sorting.h"
#include <iostream>
using namespace std;

static void merge(vector<SuspiciousCaller>& arr, int left, int mid, int right) {
    vector<SuspiciousCaller> L(arr.begin() + left,  arr.begin() + mid + 1);
    vector<SuspiciousCaller> R(arr.begin() + mid + 1, arr.begin() + right + 1);

    int i = 0, j = 0, k = left;
    while (i < (int)L.size() && j < (int)R.size()) {
        bool takeLeft = (L[i].suspicion_score > R[j].suspicion_score) ||
                        (L[i].suspicion_score == R[j].suspicion_score &&
                         L[i].total_calls     >= R[j].total_calls);
        arr[k++] = takeLeft ? L[i++] : R[j++];
    }
    while (i < (int)L.size()) arr[k++] = L[i++];
    while (j < (int)R.size()) arr[k++] = R[j++];
}

static void mergeSort(vector<SuspiciousCaller>& arr, int left, int right) {
    if (left >= right) return;
    int mid = left + (right - left) / 2;
    mergeSort(arr, left, mid);
    mergeSort(arr, mid + 1, right);
    merge(arr, left, mid, right);
}

vector<SuspiciousCaller> rankCallers(vector<SuspiciousCaller> callers) {
    if (callers.empty()) return callers;
    mergeSort(callers, 0, (int)callers.size() - 1);
    cout << "[M5] Ranked " << callers.size() << " suspicious callers by score\n";
    return callers;
}
