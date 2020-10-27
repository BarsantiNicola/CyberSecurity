
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress , int socket ){

        this->IPaddress = IPaddress;
        this->socket = socket;
        this->nonce = nullptr;

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

    int* ClientInformation::getNonce(){

        if( !this->nonce )
            return nullptr;

        return new int(*(this->nonce));

    }

    void ClientInformation::updateNonce(){

        *(this->nonce) += 1;

    }

    void ClientInformation::setNonce( int nonce ){

        this->nonce = new int(nonce);

    }

    void ClientInformation::updateIP(int port) {
        int pos = this->IPaddress.find(":" );
        if( pos != std::string::npos )
            this->IPaddress = this->IPaddress.substr(0,pos);
        this->IPaddress.append(":").append( to_string(port).c_str());
    }



}