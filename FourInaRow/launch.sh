#!/bin/bash 

export 

UTILITY_PACKAGE="src/utility/NetMessage.cpp src/utility/Message.cpp src/utility/Converter.cpp"
CIPHER_PACKAGE="src/cipher/CipherRSA.cpp"
MAIN_PACKAGE="src/main.cpp src/Logger.cpp"

g++ $UTILITY_PACKAGE $CIPHER_PACKAGE $MAIN_PACKAGE -o program -lssl -lcrypto

./program
rm program

