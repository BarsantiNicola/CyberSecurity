#!/bin/bash 

export 

UTILITY_PACKAGE="src/utility/NetMessage.cpp src/utility/Message.cpp src/utility/Converter.cpp src/utility/ConnectionManager.cpp"
CIPHER_PACKAGE="src/cipher/CipherRSA.cpp src/cipher/CipherDH.cpp src/cipher/CipherHASH.cpp src/cipher/CipherServer.cpp src/cipher/CipherAES.cpp"
MAIN_PACKAGE="src/Logger.cpp"
SERVER_PACKAGE="src/server/SQLConnector.cpp src/server/ClientInformation.cpp src/server/UserInformation.cpp src/server/MatchInformation.cpp src/server/ClientRegister.cpp src/server/MatchRegister.cpp src/server/UserRegister.cpp src/server/MainServer.cpp"
CLIENT_PACKAGE=""

if ! test -f "server"; then
	echo "Creation of server executable.."
	g++ $UTILITY_PACKAGE $CIPHER_PACKAGE $MAIN_PACKAGE $SERVER_PACKAGE $CLIENT_PACKAGE -o server -lssl -lcrypto -lmysqlcppconn 
fi

./server


