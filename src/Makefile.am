TARGET_FLAGS =
DEV_FLAGS =
if DEBUG
TARGET_FLAGS += -g -O0
DEV_FLAGS += -g -O0 -DDEBUG
else
TARGET_FLAGS += -Os
DEV_FLAGS += -Os
endif

AM_CFLAGS = -std=c11 -pedantic -Wall -Wextra -Wno-switch -Wno-unused-parameter -D_GNU_SOURCE $(DEV_FLAGS)

noinst_LIBRARIES = libproone.a
bin_PROGRAMS = proone proone-packer proone-unpacker proone-list-arch proone-mask proone-print-all-data

libproone_a_SOURCES =\
	proone_protocol.c\
	proone_pack.c\
	proone_dvault.c\
	proone_data.c\
	proone_util.c\
	proone_rnd.c

proone_LDFLAGS = -static
proone_LDADD = libproone.a $(DEP_LIBS) -lrt
proone_SOURCES =\
	proone_worker.c\
	proone_heartbeat-worker.c\
	proone.c

proone_packer_LDADD = libproone.a
proone_packer_SOURCES = proone-packer.c

proone_unpacker_LDADD = libproone.a
proone_unpacker_LDFLAGS = $(DEP_LIBS)
proone_unpacker_SOURCES = proone-unpacker.c

proone_list_arch_LDADD = libproone.a
proone_list_arch_SOURCES = proone-list-arch.c

proone_mask_LDADD = libproone.a
proone_mask_SOURCES = proone-mask.c

proone_print_all_data_LDADD = libproone.a
proone_print_all_data_SOURCES = proone-print-all-data.c

if TESTS
endif
