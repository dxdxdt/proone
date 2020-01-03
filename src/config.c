#include "config.h"


const prne_arch_t prne_host_arch =
#ifdef __GNUC__
	#if defined(__ARM_ARCH_4T__)
		PRNE_ARCH_ARMV4T
	#elif defined(__ARM_ARCH_7A__)
		PRNE_ARCH_ARMV7
	#elif defined(__x86_64__) || defined(__i386__)
		PRNE_ARCH_I686
	#elif defined(__m68k__)
		PRNE_ARCH_M68K
	#elif defined(__mips__)
		#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
			PRNE_ARCH_MIPS
		#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
			PRNE_ARCH_MPSL
		#else
			#error "FIXME!"
		#endif
	#elif defined(__powerpc__)
		PRNE_ARCH_PPC
	#elif defined(__riscv) || defined(__riscv__)
		#if __riscv_xlen == 32
			PRNE_ARCH_RV32
		#elif __riscv_xlen == 64
			PRNE_ARCH_RV64
		#else
			#error "FIXME!"
		#endif
	#elif defined(__SH4__)
		PRNE_ARCH_SH4
	#elif defined(__sparc__)
		PRNE_ARCH_SPC
	#else
		#error "FIXME!"
	#endif
#else
	#error "FIXME!"
#endif
	;
