CFLAGS = -Wall -Wextra
LDFLAGS = -lxtables -fPIC -shared

%.so : %.c
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@

all: libipt_FAKETCP.so

clean:
	rm -f *.so

install:
	install -m 755 -t /lib/iptables/ *.so
