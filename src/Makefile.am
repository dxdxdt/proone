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
bin_PROGRAMS = proone proone-pack proone-unpack proone-list-arch proone-mask proone-print-all-data

libproone_a_SOURCES =\
	protocol.c\
	pack.c\
	dvault.c\
	data.c\
	util_rt.c\
	rnd.c

proone_LDFLAGS = -static
proone_LDADD = libproone.a $(DEP_PKGCFG_LIBS) $(LIBS) -lrt -lpthread
proone_SOURCES =\
	worker.c\
	heartbeat-worker.c\
	proone.c

proone_pack_LDADD = libproone.a
proone_pack_LDFLAGS = $(DEP_PKGCFG_LIBS) $(LIBS)
proone_pack_SOURCES = proone-pack.c

proone_unpack_LDADD = libproone.a
proone_unpack_LDFLAGS = $(DEP_PKGCFG_LIBS) $(LIBS)
proone_unpack_SOURCES = proone-unpack.c

proone_list_arch_LDADD = libproone.a
proone_list_arch_LDFLAGS = $(DEP_PKGCFG_LIBS) $(LIBS)
proone_list_arch_SOURCES = proone-list-arch.c

proone_mask_LDADD = libproone.a
proone_mask_LDFLAGS = $(DEP_PKGCFG_LIBS) $(LIBS)
proone_mask_SOURCES = proone-mask.c

proone_print_all_data_LDADD = libproone.a
proone_print_all_data_LDFLAGS = $(DEP_PKGCFG_LIBS) $(LIBS)
proone_print_all_data_SOURCES = proone-print-all-data.c

if TESTS
endif
