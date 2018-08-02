all : pcap_test

pcap_test: 
		gcc -o pcap_test main.c -lpcap

clean:
	rm -f pcap_test
