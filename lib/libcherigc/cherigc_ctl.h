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
 * NALLOC r/o (size_t *val):
 * The current number of managed objects.
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
 */

#define	CHERIGC_CTL_GET			0
#define	CHERIGC_CTL_SET			1

#define	CHERIGC_KEY_IGNORE		0
#define	CHERIGC_KEY_NALLOC		1
#define	CHERIGC_KEY_REVOKE_DEBUGGING	2
#define	CHERIGC_KEY_TRACK_UNMANAGED	3

#endif /* !_CHERIGC_CTL_H_ */
