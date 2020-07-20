TARGET_FLAGS =
DEV_FLAGS =
if DEBUG
TARGET_FLAGS += -g -O0
DEV_FLAGS += -g -O0 -DPRNE_DEBUG
else
TARGET_FLAGS += -Os
DEV_FLAGS += -Os
endif

AM_CFLAGS = -std=c11 -pedantic -Wall -Wextra -Wno-switch -Wno-unused-parameter -D_GNU_SOURCE $(DEV_FLAGS)

noinst_LIBRARIES = libproone.a
bin_PROGRAMS =\
	proone\
	proone-pack\
	proone-unpack\
	proone-list-arch\
	proone-mask\
	proone-print-all-data\
	proone-resolv

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
proone_LDADD = libproone.a $(LIBS) $(DEP_PKGCFG_LIBS) -lrt -lpthread
proone_SOURCES =\
	proone.c

proone_pack_LDADD = libproone.a
proone_pack_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_pack_SOURCES = proone-pack.c

proone_unpack_LDADD = libproone.a
proone_unpack_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_unpack_SOURCES = proone-unpack.c

proone_list_arch_LDADD = libproone.a
proone_list_arch_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_list_arch_SOURCES = proone-list-arch.c

proone_mask_LDADD = libproone.a
proone_mask_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_mask_SOURCES = proone-mask.c

proone_print_all_data_LDADD = libproone.a
proone_print_all_data_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_print_all_data_SOURCES = proone-print-all-data.c

proone_resolv_LDADD = libproone.a
proone_resolv_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_resolv_SOURCES = proone-resolv.c

if TESTS
bin_PROGRAMS += proone-test_proto proone-test_util

proone_test_proto_LDADD = libproone.a
proone_test_proto_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_test_proto_SOURCES = proone-test_proto.c

proone_test_util_LDADD = libproone.a
proone_test_util_LDFLAGS = $(LIBS) $(DEP_PKGCFG_LIBS)
proone_test_util_SOURCES = proone-test_util.c
endif
