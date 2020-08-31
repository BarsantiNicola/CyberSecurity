
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress , int socket ){

        this->IPaddress = IPaddress;
        this->socket = socket;
        this->nonce = 0;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string ClientInformation::getIPaddress(){

        return this->IPaddress;

    }

    int ClientInformation::getSocket(){

        return this->socket;

    }

    int ClientInformation::getNonce(){

        return this->nonce;

    }

    void ClientInformation::updateNonce(){

        this->nonce++;

    }

    void ClientInformation::setNonce( int nonce ){

        this->nonce = nonce;

    }



}