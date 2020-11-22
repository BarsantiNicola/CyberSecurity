
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress , int socket ){

        this->IPaddress = IPaddress;
        this->socket = socket;
        this->nonce = nullptr;
        this->sendNonce = nullptr;
        this->receiveNonce = nullptr;

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

    int* ClientInformation::getReceiveNonce(){

        if( !this->receiveNonce )
            return nullptr;

        return new int(*(this->receiveNonce));

    }

    int* ClientInformation::getSendNonce(){

        if( !this->sendNonce )
            return nullptr;

        return new int(*(this->sendNonce));

    }

    void ClientInformation::updateSendNonce(){

        *(this->sendNonce) += 1;

    }

    void ClientInformation::updateReceiveNonce( int nonce ){

        *(this->receiveNonce) = nonce;

    }

    void ClientInformation::setNonce( int nonce ){

        string snonce = to_string( nonce );
        this->nonce = new int(nonce);
        this->sendNonce = new int(atoi(snonce.substr(snonce.length()/2, snonce.length()).c_str())*10000);
        this->receiveNonce = new int(atoi(snonce.substr(0,snonce.length()/2).c_str())*10000);

    }

    void ClientInformation::updateIP(int port) {
        int pos = this->IPaddress.find(":" );
        if( pos != std::string::npos )
            this->IPaddress = this->IPaddress.substr(0,pos);
        this->IPaddress.append(":").append( to_string(port).c_str());
    }



}