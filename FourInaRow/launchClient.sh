#!/bin/bash 

export 

UTILITY_PACKAGE="src/utility/NetMessage.cpp src/utility/Message.cpp src/utility/Converter.cpp src/utility/ConnectionManager.cpp"
CIPHER_PACKAGE="src/cipher/CipherRSA.cpp src/cipher/CipherDH.cpp src/cipher/CipherHASH.cpp src/cipher/CipherClient.cpp src/cipher/CipherAES.cpp"
MAIN_PACKAGE="src/Logger.cpp"
SERVER_PACKAGE="src/server/SQLConnector.cpp src/server/ClientInformation.cpp src/server/UserInformation.cpp src/server/MatchInformation.cpp src/server/ClientRegister.cpp src/server/MatchRegister.cpp src/server/UserRegister.cpp"
CLIENT_PACKAGE="src/client/ChallengeInformation.cpp src/client/Game.cpp src/client/MainClient.cpp src/client/TextualInterfaceManager.cpp src/client/ChallengeRegister.cpp"

g++ $UTILITY_PACKAGE $CIPHER_PACKAGE $MAIN_PACKAGE $SERVER_PACKAGE $CLIENT_PACKAGE -o program -lssl -lcrypto -lmysqlcppconn

echo -n "Insert socket: "
read SOCKET
./program $SOCKET
rm program

