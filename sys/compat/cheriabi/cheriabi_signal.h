
#ifndef _COMPAT_CHERIABI_CHERIABI_SIGNAL_H_
#define _COMPAT_CHERIABI_CHERIABI_SIGNAL_H_

union sigval_c {
	int			sival_int;
	struct chericap		sival_ptr;
	/* XXX: no 6.0 compatibility (sigval_*) */
};

struct siginfo_c {
	int		si_signo;
	int		si_errno;
	int		si_code;
	__pid_t		si_pid;
	__uid_t		si_uid;
	int		si_status;
	uintptr_t	si_addr;	/* PCC relative offset of faulting */
					/* instruction */
	union sigval_c	si_value;
	union   {
		struct {
			int     _trapno;	/* machine specific trap code */
		} _fault;
		struct {
			int     _timerid;
			int     _overrun;
		} _timer;
		struct {
			int     _mqd;
		} _mesgq;
		struct {
			long    _band;		/* band event for SIGPOLL */
		} _poll;			/* was this ever used ? */
		struct {
			long    __spare1__;
			int     __spare2__[7];  
		} __spare__;
	} _reason;
};

struct sigevent_c {
	int	sigev_notify;
	int	sigev_signo;
	union sigval_c sigev_value;
	union {
		__lwpid_t	_threadid;
		struct {
			void (*_function)(union sigval);
			struct chericap	*_attribute;
		} _sigev_thread;
		unsigned short _kevent_flags;
		long __spare__[8];
	} _sigev_un;
};

struct sigevent;
int convert_sigevent_c(struct sigevent_c *sig_c, struct sigevent *sig);
void siginfo_to_siginfo_c(const siginfo_t *src, struct siginfo_c *dst);

#endif /* _COMPAT_CHERIABI_CHERIABI_SIGNAL_H_ */
