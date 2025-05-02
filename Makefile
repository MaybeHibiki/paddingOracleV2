main: main.cpp
	g++ -std=c++17 AES128IV.cpp -o aes128IV -lcryptopp

clean:
	rm aes256CBCTest > /dev/null 2>&1
