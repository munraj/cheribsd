/*-
 * Copyright (c) 2012-2015 Robert N. M. Watson
 * Copyright (c) 2014-2015 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/stat.h>

#include <machine/cheri.h>
#include <machine/cheric.h>

#include <cheri/cheri_enter.h>
#include <cheri/cheri_fd.h>
#include <cheri/cheri_invoke.h>
#include <cheri/cheri_memcpy.h>
#include <cheri/cheri_system.h>

#include <inttypes.h>
#include <md5.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define	CHERITEST_INTERNAL
#include "cheritest-helper.h"
#include "cheritest-helper-internal.h"

int	invoke(void) __attribute__((cheri_ccall));
int
invoke(void)
{

	return (-1);
}

int
invoke_abort(void)
{

	abort();
}

int
invoke_md5(size_t len, char *data_input, char *data_output)
{
	MD5_CTX md5context;
	char buf[33], ch;
	u_int count;

	MD5Init(&md5context);
	for (count = 0; count < len; count++) {
		/* XXXRW: Want a CMD5Update() to avoid copying byte by byte. */
		ch = data_input[count];
		MD5Update(&md5context, &ch, sizeof(ch));
	}
	MD5End(&md5context, buf);
	for (count = 0; count < sizeof(buf); count++)
		data_output[count] = buf[count];

	return (123456);
}

#define	N	10
int
invoke_cap_fault(register_t op)
{
	char buffer[N], ch, *cap;

	switch (op) {
	case CHERITEST_HELPER_CAP_FAULT_CP2_BOUND:
		cap = cheri_ptrperm(buffer, sizeof(buffer), CHERI_PERM_LOAD);
		ch = cap[N];
		return (ch);

	case CHERITEST_HELPER_CAP_FAULT_CP2_PERM_LOAD:
		cap = cheri_ptrperm(buffer, sizeof(buffer), CHERI_PERM_STORE);
		ch = cap[0];
		return (ch);

	case CHERITEST_HELPER_CAP_FAULT_CP2_PERM_STORE:
		cap = cheri_ptrperm(buffer, sizeof(buffer), CHERI_PERM_LOAD);
		cap[0] = 0;
		return (0);

	case CHERITEST_HELPER_CAP_FAULT_CP2_TAG:
		cap = cheri_ptrperm(buffer, sizeof(buffer), CHERI_PERM_LOAD);
		cap = cheri_cleartag(cap);
		ch = cap[0];
		return (ch);

	case CHERITEST_HELPER_CAP_FAULT_CP2_SEAL:
		cap = cheri_ptrperm(buffer, sizeof(buffer), CHERI_PERM_LOAD);
		cap = cheri_seal(cap, cheri_maketype(&buffer,
		    CHERI_PERM_GLOBAL | CHERI_PERM_SEAL));
		ch = cap[0];
		return (ch);
	}
	return (0);
}

/*
 * NB: Can't use NULL to generate VM faults when compiling with pointers as
 * capabilities, as NULL generates an untagged capability.  Instead, use
 * near-NULL values.
 */
int
invoke_vm_fault(register_t op)
{
	volatile char *chp;
	char ch;

	chp = (void *)4;
	switch (op) {
	case CHERITEST_HELPER_VM_FAULT_RFAULT:
		ch = chp[0];
		break;

	case CHERITEST_HELPER_VM_FAULT_WFAULT:
		chp[0] = 0;
		break;

	case CHERITEST_HELPER_VM_FAULT_XFAULT:
		// It's no longer easy to trigger a TLB execute fault from C code,
		// because all function pointers are derived from PCC and so will
		// either be executable or generate capability faults that have a
		// higher precedence than the TLB faults.  We could map a
		// non-executable page into PCC for this test, but it's easier to just
		// do a MIPS jump.
		__asm__ volatile ("jal 4" : : :"memory");
		break;
	}
	return (0);
}

int
invoke_syscall(void)
{

	/*
	 * Invoke getpid() to trigger kernel protection features.  Should
	 * mostly be a nop.
	 */
	__asm__ __volatile__ ("syscall 20");

	return (123456);
}

int
invoke_fd_fstat_c(struct cheri_object fd_object)
{
	struct cheri_fd_ret ret;
	struct stat sb;
	void *sb_c;

	sb_c = cheri_ptr(&sb, sizeof(sb));
	ret = cheri_fd_fstat_c(fd_object, sb_c);
	return (ret.cfr_retval0);
}

int
invoke_fd_lseek_c(struct cheri_object fd_object)
{
	struct cheri_fd_ret ret;

	ret = cheri_fd_lseek_c(fd_object, 0, SEEK_SET);
	return (ret.cfr_retval0);
}

int
invoke_fd_read_c(struct cheri_object fd_object, void *buf, size_t nbytes)
{
	struct cheri_fd_ret ret;

	ret = cheri_fd_read_c(fd_object, buf, nbytes);
	return (ret.cfr_retval0);
}

int
invoke_fd_write_c(struct cheri_object fd_object, char *arg, size_t nbytes)
{

	return (cheri_fd_write_c(fd_object, arg, nbytes).cfr_retval0);
}

int
invoke_malloc(void)
{
	size_t i;
	void *tmp;
	const size_t sizes[] = {1, 2, 4, 8, 16, 32, 64, 128, 1024, 4096, 10000};

	for (i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		tmp = malloc(sizes[i]);
		if (tmp == NULL)
			return (-i);
		free(tmp);
	}
	return (0);
}

register_t
invoke_spin()
{

	while(1);

	abort();
}

int
invoke_system_calloc(void)
{
	size_t i;
	void *tmp;
	const size_t sizes[] = {1, 2, 4, 8, 16, 32, 64, 128, 1024, 4096, 10000};

	for (i = 0; i < sizeof(sizes) / sizeof(*sizes); i++) {
		if (cheri_system_calloc(1, sizes[i], &tmp) != 0)
			return (-1);
		if (tmp == NULL)
			return (-1);
		if (cheri_getlen(tmp) != sizes[i])
			return (-1);
		if (cheri_system_free(tmp) != 0)
			return (-1);
	}
	return (0);
}

int
invoke_clock_gettime(void)
{
	struct timespec t;

	if (clock_gettime(CLOCK_REALTIME, &t) == -1)
		return (-1);
	return (0);
}

int
invoke_libcheri_userfn(register_t arg, size_t len)
{

	/*
	 * Argument passed to the cheritest-helper method turns into the
	 * method number for the underlying system class invocation.
	 */
	return (cheri_system_user_call_fn(arg,
	    len, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL));
}

int
invoke_libcheri_userfn_setstack(register_t arg)
{
	int v;

	/*
	 * In the setstack test, ensure that execution of the return path via
	 * the sandbox has a visible effect that can be tested for.
	 */
	v = (cheri_system_user_call_fn(CHERITEST_USERFN_SETSTACK,
	    arg, 0, 0, 0, 0, 0, 0,
	    NULL, NULL, NULL, NULL, NULL));
	v += 10;
	return (v);
}

void *saved_capability;
int
invoke_libcheri_save_capability_in_heap(void *data_input)
{

	saved_capability = data_input;
	return (0);
}

/*
 * A series of variables whose values will be set via BSS, preinitialised data
 * in the binary, and a constructor, along with methods to query them.  Access
 * them through volatile pointers to ensure that constant memory accesses are
 * not optimised to instruction immediates in code generation, and that
 * constant initialisation is not converted from .data + a constructor to
 * static .data.
 */
static register_t cheritest_var_bss;
static register_t cheritest_var_data = CHERITEST_VALUE_DATA;
static register_t cheritest_var_constructor = CHERITEST_VALUE_INVALID;

static __attribute__ ((constructor)) void
cheritest_helper_var_constructor_init(void)
{
	volatile register_t *cheritest_var_constructorp =
	    &cheritest_var_constructor;

	*cheritest_var_constructorp = CHERITEST_VALUE_CONSTRUCTOR;
}

register_t
invoke_get_var_bss(void)
{
	volatile register_t *cheritest_var_bssp = &cheritest_var_bss;

	return (*cheritest_var_bssp);
}

register_t
invoke_get_var_data(void)
{
	volatile register_t *cheritest_var_datap = &cheritest_var_data;

	return (*cheritest_var_datap);
}

register_t
invoke_set_var_data(register_t v)
{

	volatile register_t *cheritest_var_datap = &cheritest_var_data;

	*cheritest_var_datap = v;
	return (0);
}

register_t
invoke_get_var_constructor(void)
{
	volatile register_t *cheritest_var_constructorp =
	    &cheritest_var_constructor;

	return (*cheritest_var_constructorp);
}

register_t
invoke_inflate(struct zstream_proxy *zspp)
{
	z_stream zs;

	zs.zalloc = Z_NULL;
	zs.zfree = Z_NULL;
	zs.next_in = zspp->next_in;
	zs.avail_in = zspp->avail_in;
	zs.next_out = zspp->next_out;
	zs.avail_out = zspp->avail_out;
	if (inflateInit(&zs) != Z_OK) {
		printf("inflateInit");
		abort();
	}
	if (inflate(&zs, Z_FINISH) != Z_STREAM_END) {
		printf("inflate");
		abort();
	}
	if (inflateEnd(&zs) != Z_OK) {
		printf("inflateEnd");
		abort();
	}
	zspp->next_in = zs.next_in;
	zspp->avail_in = zs.avail_in;
	zspp->next_out = zs.next_out;
	zspp->avail_out = zs.avail_out;
	zspp->total_in = zs.total_in;
	zspp->total_out = zs.total_out;
	return (0);
}

static volatile int zero = 0;
int
invoke_divzero(void)
{

	return (1/(zero));
}

int
invoke_cheri_system_helloworld(void)
{

	return (cheri_system_helloworld());
}

int
invoke_cheri_system_puts(void)
{

	return (cheri_system_puts("sandbox cs_puts"));
}

int
invoke_cheri_system_putchar(void)
{

	return (cheri_system_putchar('C'));	/* Is for cookie. */
}

int
invoke_cheri_system_printf(void)
{

	return (printf("%s: printf in sandbox test\n", __func__));
}

int
call_invoke_md5(size_t len, char *data_input, char *data_output)
{

	return (invoke_md5(len, data_input, data_output));
}

int
sandbox_test_ptrdiff(void)
{
	const int n = 100;
	char array[n];
	char *p1, *p2;
	ptrdiff_t diff;

	p1 = &array[0];
	p2 = &array[1];
	diff = p2 - p1;
	if (diff != 1) {
		printf("expected diff = 1, got diff = %jd\n", (intmax_t)diff);
		return (-1);
	}
	p1 = &array[0];
	p2 = &array[n];
	diff = p2 - p1;
	if (diff != n) {
		printf("expected diff = %d, got diff = %jd\n", n,
		    (intmax_t)diff);
		return (-1);
	}

	return (0);
}

static const int	vd_int = 0x1234;
static const long	vd_long = 0x123456789LL;
static const char	vd_string[] = "a test string";

struct var_data {
	int	 vd_int;
	long	 vd_long;
	char	*vd_string;
/*
	int	(*vd_func)(void);
*/
};

/*
 * Expects to find arguments in the following order:
 *   int, long, char*, function pointer
 */
static void
vfill_var_data(struct var_data *vdp, va_list ap)
{

	vdp->vd_int = va_arg(ap, int);
	vdp->vd_long = va_arg(ap, long);
	vdp->vd_string = va_arg(ap, char *);
}

static void
fill_var_data(struct var_data *vdp, ...)
{
	va_list ap;
	
	va_start(ap, vdp);
	vfill_var_data(vdp, ap);
	va_end(ap);
}

static int
check_var_data(struct var_data *vdp)
{

	if (vdp->vd_int != vd_int)
		return (-2);
	if (vdp->vd_long != vd_long)
		return (-3);
	if (strcmp(vdp->vd_string, vd_string) != 0)
		return (-4);

	return (0);
}

int
sandbox_test_varargs(void)
{
	struct var_data vd;

	fill_var_data(&vd, vd_int, vd_long, vd_string);

	return (check_var_data(&vd));
}

static void
fill_var_data_from_copy(struct var_data *vdp, ...)
{
	va_list ap, ap_copy;

	va_start(ap, vdp);
	va_copy(ap_copy, ap);
	va_end(ap);
	vfill_var_data(vdp, ap_copy);
	va_end(ap_copy);
}

int
sandbox_test_va_copy(void)
{
	struct var_data vd;

	fill_var_data_from_copy(&vd, vd_int, vd_long, vd_string);

	return (check_var_data(&vd));
}
