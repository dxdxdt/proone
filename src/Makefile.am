TARGET_FLAGS =
DEV_FLAGS =
if DEBUG
TARGET_FLAGS += -g -O0
DEV_FLAGS += -g -O0
else
TARGET_FLAGS += -Os
DEV_FLAGS += -Os
endif

noinst_LIBRARIES = libproone.a
bin_PROGRAMS = proone proone-packer proone-unpacker proone-list-arch

libproone_a_SOURCES =\
	proone_protocol.c\
	proone_pack.c

proone_CFLAGS = -std=c11 -Wall -Wno-switch $(DEV_FLAGS)
proone_LDFLAGS = -static
proone_LDADD = libproone.a $(DEP_LIBS)
proone_SOURCES =\
	proone.c

proone_packer_CFLAGS = -std=c11 -Wall -Wno-switch $(DEV_FLAGS)
proone_packer_LDADD = libproone.a
proone_packer_SOURCES = proone-packer.c
proone_unpacker_CFLAGS = -std=c11 -Wall -Wno-switch $(DEV_FLAGS)
proone_unpacker_LDADD = libproone.a
proone_unpacker_LDFLAGS = $(DEP_LIBS)
proone_unpacker_SOURCES = proone-unpacker.c
proone_list_arch_CFLAGS = -std=c11 -Wall -Wno-switch $(DEV_FLAGS)
proone_list_arch_LDADD = libproone.a
proone_list_arch_SOURCES = proone-list-arch.c

if TESTS
endif
