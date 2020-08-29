
#include "ClientInformation.h"

namespace server{

    ClientInformation::ClientInformation( string IPaddress , int socket ){

        this->IPaddress = IPaddress;
        this->socket = socket;

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



}