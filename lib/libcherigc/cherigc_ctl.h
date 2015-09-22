#ifndef _CHERIGC_CTL_H_
#define _CHERIGC_CTL_H_

/*
 * cherigc_ctl: Configure the collector.
 *
 * Args:
 * cmd: one of CHERIGC_CTL_*.
 * key: cmd-specific; one of CHERIGC_KEY_*.
 * val: key-specific input or output value.
 *
 * Return values: 0 iff success.
 *
 * GET: get a value.
 * SET: set a value.
 *
 * Keys:
 *
 * IGNORE r/w (int *val, def = 0):
 * When non-zero, any new allocations will be ignored by the collector.
 *
 * REVOKE_DEBUGGING r/w (int *val, def = 0):
 * If set, revoked objects will remain allocated (and not have free()
 * called on them) in the tables, but still invalidated as normal. Useful
 * for determining whether the collector really is invalidating revoked
 * capabilities.
 *
 * TRACK_UNMANAGED r/w (int *val, def = 1):
 * If set, unmanaged objects will be scanned. Useful to disable this in,
 * for example, a test that tests the lookup tables for correctness and
 * creates invalid but tagged capabilities. The GC always checks whether it
 * can read pages referenced this way, and should only become more
 * conservative as a result of enabling this; however, there may be a large
 * performance hit if the range of the capability is very large.
 *
 * STATS_INCREMENTAL r/o (struct cherigc_stats *cs):
 * Retrieve incremental statistics that the GC has gathered. See also
 * STATS_FULL.
 * NOTE: If you can't decide between STATS_INCREMENTAL and STATS_FULL, you
 * probably want STATS_INCREMENTAL.
 *
 * STATS_FULL r/o (struct cherigc_stats *cs):
 * Retrieve the statistics as stored in the VM tables. Can be used for
 * integrity checking: if both STATS_FULL and STATS_INCREMENTAL do not
 * return the same result, there's likely a bug in the collector. (This may
 * not apply if some debugging features are in use; for example, the revoke
 * counts may be different if REVOKE_DEBUGGING is set. It also does not
 * apply for statistics that don't make sense for STATS_FULL, like pause
 * times).
 * NOTE: If you can't decide between STATS_INCREMENTAL and STATS_FULL, you
 * probably want STATS_INCREMENTAL.
 */

#define	CHERIGC_CTL_GET			0
#define	CHERIGC_CTL_SET			1

#define	X_CHERIGC_KEY							\
	X(CHERIGC_KEY_IGNORE,			0)			\
	X(CHERIGC_KEY_REVOKE_DEBUGGING,		1)			\
	X(CHERIGC_KEY_TRACK_UNMANAGED,		2)			\
	X(CHERIGC_KEY_STATS_INCREMENTAL,	3)			\
	X(CHERIGC_KEY_STATS_FULL,		4)

enum cherigc_key_enum {
#define	X(c, n)	c = n,
	X_CHERIGC_KEY
#undef	X
};

#define	PRIgc_time	PRIu64 " ms"

#endif /* !_CHERIGC_CTL_H_ */
