
#ifndef FOURINAROW_CLIENTREGISTER_H
#define FOURINAROW_CLIENTREGISTER_H

#include "ClientInformation.h"
#include "../Logger.h"
#include <vector>
using namespace utility;

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   CLIENT REGISTER                                 //
    //    The class maintans information about the connected clients(socket and ip)      //
    //    It permits easely to add or remove a client basing on its socket and a search  //
    //    into the archive to know if a client is present or get its net address.        //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class ClientRegister {

        private:
            vector<ClientInformation> clientRegister;

        public:
            bool   addClient( string ip , int socket );      // ADD NEW CLIENT
            bool   removeClient( int socket );               // REMOVE A CLIENT
            bool   has( int socket );                        // SEARCH IF A SOCKET IS PRESENT
            string getClientNetInformation( int socket );    // RETURN THE CLIENT IP ADDRESS
            unsigned int*   getClientNonce( int socket );             // RETURN THE NONCE USED TO SEND MESSAGES TO THE CLIENT
            unsigned int*   getClientReceiveNonce( int socket );      // RETURN THE NONCE USED TO RECEIVE MESSAGES FROM THE CLIENT
            bool   updateClientNonce( int socket );          // UPDATE THE NONCE USED TO SEND MESSAGES TO THE CLIENT
            bool   updateClientReceiveNonce( int socket, int nonce );  //  UPDATE THE NONCE USED TO RECEIVE MESSAGE FROM THE CLIENT
            bool   setClientReceiveNonce( int socket , unsigned int nonce );       // SET THE NONCE FOR A CLIENT AND DERIVES THE SEND/RECEIVE NONCE FROM IT
            bool   setClientSendNonce( int socket , unsigned int nonce );       // SET THE NONCE FOR A CLIENT AND DERIVES THE SEND/RECEIVE NONCE FROM IT
            bool   updateIp( int socket, int port );         // UPDATE THE SAVED IP ADDRESS FOR THE CLIENT(USED TO INSERT THE PORT AFTER A LOGIN)

    };

}


#endif //FOURINAROW_CLIENTREGISTER_H
