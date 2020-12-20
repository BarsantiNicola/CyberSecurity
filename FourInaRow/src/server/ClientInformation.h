
#ifndef FOURINAROW_CLIENTINFORMATION_H
#define FOURINAROW_CLIENTINFORMATION_H

#include <iostream>

using namespace std;

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CLIENT INFORMATION                              //
    //    The class maintans information about a client(the linked socket, its ip        //
    //    address and the nonce which will be used during communications.                //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

class ClientInformation{

        private:
            string IPaddress;
            int socket;
            unsigned int* receiveNonce;
            unsigned int* sendNonce;

        public:
            ClientInformation( string IPaddress, int socket );
            string getIPaddress();
            int getSocket();
            unsigned int* getSendNonce();
            unsigned int* getReceiveNonce();
            void setSendNonce( unsigned int nonce );
            void setReceiveNonce( unsigned int nonce );
            void updateIP( int port );
            void updateSendNonce();
            void updateReceiveNonce( int nonce );


    };

}

#endif //FOURINAROW_CLIENTINFORMATION_H
