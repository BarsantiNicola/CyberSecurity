
#ifndef FOURINAROW_CLIENTINFORMATION_H
#define FOURINAROW_CLIENTINFORMATION_H

#include <iostream>

using namespace std;

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CLIENT INFORMATION                              //
    //    The class maintans information about a client(the linked socket and its ip     //
    //    address                                                                        //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

class ClientInformation{

        private:
            string IPaddress;
            int socket;
            int* nonce;

        public:
            ClientInformation( string IPaddress, int socket );
            string getIPaddress();
            int getSocket();
            int* getNonce();
            void updateNonce();
            void setNonce( int nonce );
            void updateIP( int port );


    };

}

#endif //FOURINAROW_CLIENTINFORMATION_H
