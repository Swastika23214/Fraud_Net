#include <iostream>
#include <vector>
#include <fstream>   // for file writing
using namespace std;

// Structure for storing suspicious data
struct FraudRecord {
    string number;
    int score;
};

// Merge function
void merge(vector<FraudRecord>& arr, int left, int mid, int right) {
    vector<FraudRecord> temp;
    int i = left, j = mid + 1;

    while (i <= mid && j <= right) {
        if (arr[i].score > arr[j].score) { // descending order
            temp.push_back(arr[i++]);
        } else {
            temp.push_back(arr[j++]);
        }
    }

    while (i <= mid) temp.push_back(arr[i++]);
    while (j <= right) temp.push_back(arr[j++]);

    for (int k = 0; k < temp.size(); k++) {
        arr[left + k] = temp[k];
    }
}

// Merge Sort
void mergeSort(vector<FraudRecord>& arr, int left, int right) {
    if (left >= right) return;

    int mid = (left + right) / 2;
    mergeSort(arr, left, mid);
    mergeSort(arr, mid + 1, right);
    merge(arr, left, mid, right);
}

// Function to assign risk level
string getRisk(int score) {
    if (score > 85) return "High";
    else if (score > 75) return "Medium";
    else return "Low";
}

// Function to display + save results
void display(vector<FraudRecord>& arr) {
    ofstream file("output.txt");  // file for UI

    cout << "\n--- Ranked Suspicious Numbers ---\n";

    for (auto &x : arr) {
        string risk = getRisk(x.score);

        // Console output
        cout << "Number: " << x.number 
             << " | Score: " << x.score 
             << " | Risk: " << risk << endl;

        // File output (for HTML)
        file << x.number << " " << x.score << " " << risk << endl;
    }

    file.close();
}

// Test main (replace later with real data)
int main() {
    vector<FraudRecord> data = {
        {"9991110001", 90},
        {"8882220002", 75},
        {"7773330003", 85}
    };

    mergeSort(data, 0, data.size() - 1);
    display(data);

    return 0;
}
