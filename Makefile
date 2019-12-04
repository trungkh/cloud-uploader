PROG = clouduploader
#       confgen
MODULE_CFLAGS =
SOURCES = clouduploader.c gdriveuploader.c odriveuploader.c common.c
SOURCES += json/jsmn.c \
			configini/configini.c \
			crypto/aes_sw.c \
			crypto/aes.c \
			crypto/decrypt.c \
			crypto/encrypt.c

CFLAGS = -g3 -W -Wall -Wno-unused-function $(CFLAGS_EXTRA) $(MODULE_CFLAGS)
LDFLAGS =

STRIP = strip

CFLAGS += -lpthread -lcurl

all: $(PROG)

clouduploader: $(SOURCES)
	$(CC) $(SOURCES) -o $@ $(CFLAGS) $(LDFLAGS)
#	$(STRIP) $@

#confgen:
#	$(CC) confgen.c crypto/encrypt.c crypto/aes_sw.c crypto/aes.c -o $@ $(CFLAGS) $(LDFLAGS)
#	$(STRIP) $@

clean:
	rm -rf *.gc* *.dSYM *.exe *.obj *.o a.out $(PROG)

