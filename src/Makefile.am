# TODO: Use -D_POSIX_C_SOURCE=200112L or -D_POSIX_C_SOURCE=2
AM_CFLAGS = -std=c11 -pedantic -Wall -Wextra -Wno-switch -D_GNU_SOURCE -Wno-unused-parameter
if DEBUG
AM_CFLAGS += -g -O0 -DPRNE_DEBUG
else
AM_CFLAGS += -g -Os
endif

noinst_LIBRARIES = libproone.a
bin_PROGRAMS =\
	proone\
	proone-pack\
	proone-unpack\
	proone-list-arch\
	proone-mask\
	proone-print-all-data\
	proone-resolv\
	proone-stress

libproone_a_SOURCES =\
	config.c\
	protocol.c\
	pack.c\
	dvault.c\
	data.c\
	util_rt.c\
	llist.c\
	iset.c\
	imap.c\
	mbedtls.c\
	worker.c\
	resolv_worker.c

proone_LDFLAGS = -static
proone_LDADD = libproone.a
proone_SOURCES =\
	proone.c

proone_pack_LDADD = libproone.a
proone_pack_LDFLAGS =
proone_pack_SOURCES = proone-pack.c

proone_unpack_LDADD = libproone.a
proone_unpack_LDFLAGS =
proone_unpack_SOURCES = proone-unpack.c

proone_list_arch_LDADD = libproone.a
proone_list_arch_LDFLAGS =
proone_list_arch_SOURCES = proone-list-arch.c

proone_mask_LDADD = libproone.a
proone_mask_LDFLAGS =
proone_mask_SOURCES = proone-mask.c

proone_print_all_data_LDADD = libproone.a
proone_print_all_data_LDFLAGS =
proone_print_all_data_SOURCES = proone-print-all-data.c

proone_resolv_LDADD = libproone.a
proone_resolv_LDFLAGS =
proone_resolv_SOURCES = proone-resolv.c

proone_stress_LDADD = libproone.a
proone_stress_LDFLAGS = -static
proone_stress_SOURCES = proone-stress.c

if TESTS
bin_PROGRAMS += proone-test_proto proone-test_util

proone_test_proto_LDADD = libproone.a
proone_test_proto_LDFLAGS =
proone_test_proto_SOURCES = proone-test_proto.c

proone_test_util_LDADD = libproone.a
proone_test_util_LDFLAGS =
proone_test_util_SOURCES = proone-test_util.c
endif
