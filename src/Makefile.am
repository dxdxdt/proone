BIN_ALIGNMENT = 8

# TODO: Use -D_POSIX_C_SOURCE=200112L or -D_POSIX_C_SOURCE=2
AM_CFLAGS = -std=c11 -pedantic -Wall -Wextra -Wno-switch -D_GNU_SOURCE -Wno-unused-parameter -DPRNE_BIN_ALIGNMENT=$(BIN_ALIGNMENT)
if DEBUG
AM_CFLAGS += -g -O0 -DPRNE_DEBUG
else
AM_CFLAGS += -g -Os
endif

noinst_LIBRARIES = libproone.a
my_DATA = proone testlist
mydir = $(bindir)
bin_PROGRAMS =\
	proone.bin\
	proone-mkdvault\
	proone-pack\
	proone-unpack\
	proone-list-arch\
	proone-resolv\
	proone-stress\
	proone-ipaddr-arr

proone_tests =\
	proone-test_proto\
	proone-test_util
bin_PROGRAMS += $(proone_tests)

libproone_a_SOURCES =\
	config.c\
	protocol.c\
	pack.c\
	dvault.c\
	util_rt.c\
	llist.c\
	iset.c\
	imap.c\
	mbedtls.c\
	pth.c\
	resolv.c

proone: proone.bin dvault.bin
	cp -fa proone.bin proone
	./build-utils.sh align-file $(BIN_ALIGNMENT) proone
	./build-utils.sh append-uint16 `stat -c "%s" dvault.bin` proone
	./build-utils.sh append-uint16 0 proone
	./build-utils.sh append-uint32 0 proone
	cat dvault.bin >> proone

proone_bin_LDFLAGS = -static
proone_bin_LDADD = libproone.a
proone_bin_SOURCES =\
	proone.c

dvault.bin: proone-mkdvault
	./proone-mkdvault > dvault.bin

proone_mkdvault_LDADD = libproone.a
proone_mkdvault_SOURCES = proone-mkdvault.c

proone_pack_LDADD = libproone.a
proone_pack_LDFLAGS =
proone_pack_SOURCES = proone-pack.c

proone_unpack_LDADD = libproone.a
proone_unpack_LDFLAGS =
proone_unpack_SOURCES = proone-unpack.c

proone_list_arch_LDADD = libproone.a
proone_list_arch_LDFLAGS =
proone_list_arch_SOURCES = proone-list-arch.c

proone_resolv_LDADD = libproone.a
proone_resolv_LDFLAGS =
proone_resolv_SOURCES = proone-resolv.c

proone_ipaddr_arr_SOURCES = proone-ipaddr-arr.c

proone_stress_LDADD = libproone.a
proone_stress_LDFLAGS = -static
proone_stress_SOURCES = proone-stress.c

proone_test_proto_LDADD = libproone.a
proone_test_proto_LDFLAGS =
proone_test_proto_SOURCES = proone-test_proto.c

proone_test_util_LDADD = libproone.a
proone_test_util_LDFLAGS =
proone_test_util_SOURCES = proone-test_util.c

testlist: $(proone_tests)
	echo $(proone_tests) > testlist
