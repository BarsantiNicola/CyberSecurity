#!/bin/bash 

export 

UTILITY_PACKAGE="src/utility/NetMessage.cpp src/utility/Message.cpp src/utility/Converter.cpp src/utility/Register.cpp"
CIPHER_PACKAGE="src/cipher/CipherRSA.cpp src/cipher/CipherDH.cpp src/cipher/CipherHASH.cpp"
MAIN_PACKAGE="src/main.cpp src/Logger.cpp"
SERVER_PACKAGE="src/server/SQLConnector.cpp"
CLIENT_PACKAGE=""

g++ $UTILITY_PACKAGE $CIPHER_PACKAGE $MAIN_PACKAGE $SERVER_PACKAGE $CLIENT_PACKAGE -o program -lssl -lcrypto -lmysqlcppconn

./program
rm program

