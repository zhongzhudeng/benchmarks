#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>

#include <utils.h>

/** DPDK implementation to get TSC freq. This is a workaround
 *  so that we don't have to bind a core to DPK.
 */
/** All this timing information only works on x86 processors */

static uint64_t tsc_freq;

#define US_PER_S 1000000
#define bit_AVX		(1 << 28)

#define ALIGN_MUL_FLOOR(v, mul) \
	(((v) / ((typeof(v))(mul))) * (typeof(v))(mul))

#define ALIGN_MUL_CEIL(v, mul) \
	((((v) + (typeof(v))(mul) - 1) / ((typeof(v))(mul))) * (typeof(v))(mul))

#define ALIGN_MUL_NEAR(v, mul)				\
	({							\
		typeof(v) ceil = ALIGN_MUL_CEIL(v, mul);	\
		typeof(v) floor = ALIGN_MUL_FLOOR(v, mul);	\
		(ceil - (v)) > ((v) - floor) ? floor : ceil;	\
	})

#define __cpuid(level, a, b, c, d)			\
  __asm__ ("cpuid\n\t"					\
	   : "=a" (a), "=b" (b), "=c" (c), "=d" (d)	\
	   : "0" (level))

static __inline unsigned int 
__get_cpuid_max (unsigned int __ext, unsigned int *__sig);
static uint32_t check_model_wsm_nhm(uint8_t model);
static uint32_t check_model_gdm_dnv(uint8_t model);
static unsigned int cpu_get_model(uint32_t fam_mod_step);
static int32_t rdmsr(int msr, uint64_t *val);
static uint64_t get_tsc_freq_arch(void);
uint64_t get_tsc_freq(void);

static __inline unsigned int 
__get_cpuid_max (unsigned int __ext, unsigned int *__sig)
{
  unsigned int __eax, __ebx, __ecx, __edx;

#ifndef __x86_64__
  /* See if we can use cpuid.  On AMD64 we always can.  */
#if __GNUC__ >= 3
  __asm__ ("pushf{l|d}\n\t"
	   "pushf{l|d}\n\t"
	   "pop{l}\t%0\n\t"
	   "mov{l}\t{%0, %1|%1, %0}\n\t"
	   "xor{l}\t{%2, %0|%0, %2}\n\t"
	   "push{l}\t%0\n\t"
	   "popf{l|d}\n\t"
	   "pushf{l|d}\n\t"
	   "pop{l}\t%0\n\t"
	   "popf{l|d}\n\t"
	   : "=&r" (__eax), "=&r" (__ebx)
	   : "i" (0x00200000));
#else
/* Host GCCs older than 3.0 weren't supporting Intel asm syntax
   nor alternatives in i386 code.  */
  __asm__ ("pushfl\n\t"
	   "pushfl\n\t"
	   "popl\t%0\n\t"
	   "movl\t%0, %1\n\t"
	   "xorl\t%2, %0\n\t"
	   "pushl\t%0\n\t"
	   "popfl\n\t"
	   "pushfl\n\t"
	   "popl\t%0\n\t"
	   "popfl\n\t"
	   : "=&r" (__eax), "=&r" (__ebx)
	   : "i" (0x00200000));
#endif

  if (!((__eax ^ __ebx) & 0x00200000))
    return 0;
#endif

  /* Host supports cpuid.  Return highest supported cpuid input value.  */
  __cpuid (__ext, __eax, __ebx, __ecx, __edx);

  if (__sig)
    *__sig = __ebx;

  return __eax;
}

static uint32_t
check_model_wsm_nhm(uint8_t model)
{
	switch (model) {
	/* Westmere */
	case 0x25:
	case 0x2C:
	case 0x2F:
	/* Nehalem */
	case 0x1E:
	case 0x1F:
	case 0x1A:
	case 0x2E:
		return 1;
	}

	return 0;
}

static uint32_t
check_model_gdm_dnv(uint8_t model)
{
	switch (model) {
	/* Goldmont */
	case 0x5C:
	/* Denverton */
	case 0x5F:
		return 1;
	}

	return 0;
}

static unsigned int
cpu_get_model(uint32_t fam_mod_step)
{
	uint32_t family, model, ext_model;

	family = (fam_mod_step >> 8) & 0xf;
	model = (fam_mod_step >> 4) & 0xf;

	if (family == 6 || family == 15) {
		ext_model = (fam_mod_step >> 16) & 0xf;
		model += (ext_model << 4);
	}

	return model;
}

static int32_t
rdmsr(int msr, uint64_t *val)
{
	int fd;
	int ret;

	fd = open("/dev/cpu/0/msr", O_RDONLY);
	if (fd < 0)
		return fd;

	ret = pread(fd, val, sizeof(uint64_t), msr);

	close(fd);

	return ret;
}

void
delay_us_sleep(unsigned int us)
{
	struct timespec wait[2];
	int ind = 0;

	wait[0].tv_sec = 0;
	if (us >= US_PER_S) {
		wait[0].tv_sec = us / US_PER_S;
		us -= wait[0].tv_sec * US_PER_S;
	}
	wait[0].tv_nsec = 1000 * us;

	while (nanosleep(&wait[ind], &wait[1 - ind]) && errno == EINTR) {
		/*
		 * Sleep was interrupted. Flip the index, so the 'remainder'
		 * will become the 'request' for a next call.
		 */
		ind = 1 - ind;
	}
}

static
uint64_t get_tsc_freq_arch(void)
{
	uint64_t tsc_hz = 0;
	uint32_t a, b, c, d, maxleaf;
	uint8_t mult, model;
	int32_t ret;

	/*
	 * Time Stamp Counter and Nominal Core Crystal Clock
	 * Information Leaf
	 */
	maxleaf = __get_cpuid_max(0, NULL);

	if (maxleaf >= 0x15) {
		__cpuid(0x15, a, b, c, d);

		/* EBX : TSC/Crystal ratio, ECX : Crystal Hz */
		if (b && c)
			return c * (b / a);
	}

	__cpuid(0x1, a, b, c, d);
	model = cpu_get_model(a);

	if (check_model_wsm_nhm(model))
		mult = 133;
	else if ((c & bit_AVX) || check_model_gdm_dnv(model))
		mult = 100;
	else
		return 0;

	ret = rdmsr(0xCE, &tsc_hz);
	if (ret < 0)
		return 0;

	return ((tsc_hz >> 8) & 0xff) * mult * 1E6;
}

uint64_t
get_tsc_freq(void)
{
#ifdef CLOCK_MONOTONIC_RAW
#define NS_PER_SEC 1E9
#define CYC_PER_10MHZ 1E7

	struct timespec sleeptime = {.tv_nsec = NS_PER_SEC / 10 }; /* 1/10 second */

	struct timespec t_start, t_end;
	uint64_t tsc_hz;

	if (clock_gettime(CLOCK_MONOTONIC_RAW, &t_start) == 0) {
		uint64_t ns, end, start = util_rdtsc();
		nanosleep(&sleeptime,NULL);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t_end);
		end = util_rdtsc();
		ns = ((t_end.tv_sec - t_start.tv_sec) * NS_PER_SEC);
		ns += (t_end.tv_nsec - t_start.tv_nsec);

		double secs = (double)ns/NS_PER_SEC;
		tsc_hz = (uint64_t)((end - start)/secs);
		/* Round up to 10Mhz. 1E7 ~ 10Mhz */
		return ALIGN_MUL_NEAR(tsc_hz, CYC_PER_10MHZ);
	}
#endif
	return 0;
}

static uint64_t
estimate_tsc_freq(void)
{
#define CYC_PER_10MHZ 1E7
	/* assume that the delay_us_sleep() will sleep for 1 second */
	uint64_t start = util_rdtsc();
	delay_us_sleep(US_PER_S);
	/* Round up to 10Mhz. 1E7 ~ 10Mhz */
	return ALIGN_MUL_NEAR(util_rdtsc() - start, CYC_PER_10MHZ);
}

uint64_t 
get_tsc_hz()
{
    return tsc_freq;
}

void 
set_tsc_freq()
{
    uint64_t freq;

    freq = get_tsc_freq_arch();
    if (!freq) {
        freq = get_tsc_freq();
    }
    if (!freq) {
	    freq = estimate_tsc_freq();
	}

    tsc_freq = freq;
}

/*************************************************************/