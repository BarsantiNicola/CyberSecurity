#!/bin/bash 

export 
CLIENT_PACKAGE="src/client/TextualInterfaceManager.cpp src/client/main.cpp src/utility/NetMessage.cpp src/utility/Logger.cpp"

g++ -classpath src/client,src/utility,src $CLIENT_PACKAGE -o client # -lssl -lcrypto

./client
rm client

