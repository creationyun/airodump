LDLIBS=-lpcap

all: airodump

airodump: main.o
	$(LINK.cc) $^ $(LDLIBS) -o $@

clean:
	rm -f airodump *.o


