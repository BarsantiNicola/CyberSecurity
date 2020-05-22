#!/bin/bash 

cd src/client
g++ TextualInterfaceManager.cpp main.cpp -o client 
./client
rm client
cd ../..
