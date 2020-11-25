
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress, int socket ){

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

        if( !this->nonce ) return nullptr;

        return new int(*(this->nonce));

    }

    int* ClientInformation::getReceiveNonce(){

        if( !this->receiveNonce ) return nullptr;

        return new int(*(this->receiveNonce));

    }

    int* ClientInformation::getSendNonce(){

        if( !this->sendNonce ) return nullptr;

        return new int(*(this->sendNonce));

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  Function to set the nonce, from the given nonce it derives two values one will be used by the client to contact
    //  the server and the other will be used from the server to reply
    void ClientInformation::setNonce( int nonce ){

        string snonce = to_string( nonce );
        this->nonce = new int(nonce);

        this->sendNonce = new int(((unsigned int)atoi(snonce.substr(snonce.length()/2, snonce.length()).c_str())*10000));
        this->receiveNonce = new int(((unsigned int)atoi(snonce.substr(0,snonce.length()/2).c_str())*10000));

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                          UTILITIES                                        //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  Update the IP mantained by the register. Used to update the port information obtained during the login phase
    void ClientInformation::updateIP(int port) {
        int pos = this->IPaddress.find(":" );
        if( pos != std::string::npos )
            this->IPaddress = this->IPaddress.substr(0,pos);
        this->IPaddress.append(":").append( to_string(port).c_str());
    }

    //  The nonce used to send messages to the client needs to be incremented after each message to prevent
    //  reply attack
    void ClientInformation::updateSendNonce(){

        *(this->sendNonce) += 1;

    }

    //  The nonce used to receive messages needs to be update after each received message to prevent reply attack.
    //  The value in case of lost messages, or particular situations could be incrementated of more than a unit.
    void ClientInformation::updateReceiveNonce( int nonce ){

        *(this->receiveNonce) = nonce;

    }

}
