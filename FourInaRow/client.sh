#!/bin/bash 

CPATH=src/client
export CPATH

CLIENT_PACKAGE="src/client/TextualInterfaceManager.cpp src/client/main.cpp"

g++ $CLIENT_PACKAGE -o client # -lssl -lcrypto

./client
rm client

