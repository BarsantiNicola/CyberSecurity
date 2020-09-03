
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

        Message* createMessage( MessageType type, bool correctness );
        void showMessage( Message* message );

    public:
        PowerClient( string ipAddr, int port );
        void sendMessage( MessageType type, bool correctness );
        void waitMessage();


};


#endif //FOURINAROW_POWERCLIENT_H
