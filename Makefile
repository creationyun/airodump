LDLIBS=-lpcap

all: airodump

airodump: main.o net-address.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f airodump *.o


