#include <vector>
#include <utility>
#include <map>
#include <iostream>
#include <inttypes.h>

// The key to access a variable
typedef std::pair<void *, int> var_key_t;
struct var_key_comp {
	bool operator()(const var_key_t &lhs, const var_key_t &rhs) {
		return ((lhs.first < rhs.first) ||
			((lhs.first == rhs.first) && (lhs.second < rhs.second)));
	}
};

// Intervals and their happens-before relation
typedef std::pair<long, long> interval_t;
bool happens_before(interval_t *lhs, interval_t *rhs) {
	return (!lhs ||  (lhs->second < rhs->first));
}

// allocates a new interval on heap
interval_t *new_interval(long clock);

// Update the exit timestamp of the current interval, speculatively, upon hitting each
// pthread_log_replay() function with *_ENTER type
// This update is speculative as it could be overwritten by the update_interval_overwrite()
// function if a context switch is detected
void update_interval_speculate(std::vector<interval_t *> &thd_ints, uint32_t tid, long clock);

// Update the exit timestamp of the current interval to the clock value at which the current
// thread is eligible to run again.
// This function is only called when a context switch is necessary.
void update_interval_overwrite(std::vector<interval_t *> &thd_ints, uint32_t tid, long clock);


// Variable data type
// Keyed by memory address and access size
class var_t {
	std::vector<interval_t *> last_wr;
	std::vector<interval_t *> last_rd;
public:
	int check_for_race(int acc_type, std::vector<interval_t *> &thd_ints, uint32_t tid);
	void update_intvls(int acc_type, const std::vector<interval_t *> &thd_ints, uint32_t tid);
	int resize_intvls(int target_size);
};
