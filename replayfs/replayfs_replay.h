#ifndef __REPLAYFS_REPLAY_H__
#define __REPLAYFS_REPLAY_H__

/* Encapsulates a replaying process */
struct replayfs_replay {
	/* Reference counting, in case it has multiple accessing files */
	atomic_t refcount;

	/* The replay log itself */
	struct syscall_log *log;
};

#endif

