
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress, int socket ){

        this->IPaddress = IPaddress;
        this->socket = socket;
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

    unsigned int* ClientInformation::getReceiveNonce(){

        if( !this->receiveNonce ) return nullptr;

        return new unsigned int(*(this->receiveNonce));

    }

    unsigned int* ClientInformation::getSendNonce(){

        if( !this->sendNonce ) return nullptr;

        return new unsigned int(*(this->sendNonce));

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  Function to set the nonce used to send messages to clients
    void ClientInformation::setSendNonce( unsigned int nonce ){

        this->sendNonce = new unsigned int(nonce);

    }

    void ClientInformation::setReceiveNonce( unsigned int nonce ){

        this->receiveNonce = new unsigned int( nonce );

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
