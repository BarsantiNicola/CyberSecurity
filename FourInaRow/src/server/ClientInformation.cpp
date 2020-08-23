
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation(int clientID, string IPaddress, int socket){

        this->clientID = clientID;
        this->IPaddress = IPaddress;
        this->socket = socket;

    }

    int ClientInformation::getClientID(){

        return this->clientID;

    }
    string ClientInformation::getIPaddress(){

        return this->IPaddress;

    }

    int ClientInformation::getSocket(){

        return this->socket;

    }

}