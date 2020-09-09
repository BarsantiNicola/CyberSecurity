
#ifndef FOURINAROW_POWERCLIENT_H
#define FOURINAROW_POWERCLIENT_H

#include"utility/Message.h"
#include<vector>
#include<stdexcept>
#include"Logger.h"
#include"utility/ConnectionManager.h"
#include "cipher/CipherRSA.h"
#include "cipher/CipherDH.h"
#include "cipher/CipherAES.h"
#include"utility/NetMessage.h"
#include<stdlib.h>
#include<iostream>
using namespace utility;

class PowerClient {

    private:
        cipher::CipherRSA *cipher,*cipher2;
        cipher::CipherDH *cipherDH;
        cipher::CipherAES* cipherAes;
        ConnectionManager *manager;
        int server_socket;
        int nonce;
        int port;
        string username;

        Message* createMessage( MessageType type, const char* param );
        void showMessage( Message* message );
        void sendMessage( MessageType type, const char* param );
        void waitMessage();
    public:
        PowerClient( string ipAddr, int port );

        void startClient();


};


#endif //FOURINAROW_POWERCLIENT_H
