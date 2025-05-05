main: 
	g++ -std=c++17 AES128IV.cpp -o aes128IV -lcryptopp
	g++ -std=c++17 tcpServer.cpp -o server -lcryptopp
	g++ -std=c++17 tcpClient.cpp -o client -lcryptopp

clean:
	rm aes128IV > /dev/null 2>&1
