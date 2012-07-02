# what a hardcore makefile

all:
	$(CXX) src/main.cpp src/Bencode.cpp -o ut-signing-tool -lcrypto