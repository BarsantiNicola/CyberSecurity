
#include "ClientRegister.h"

namespace server{

    //  add a new client connection information to the register. If the information is already present
    //  it silently discard the request[socket MUST BE unique]

    bool ClientRegister::addClient( string ip , int socket ){

        if( this->clientRegister.size() == this->clientRegister.max_size() ){

            verbose<<"--> [ClientRegister][addClient] Error, the register is full"<<'\n';
            return false;

        }

        if( this->has( socket )) {

            vverbose<<"--> [ClientRegister][addClient] Error, the register already has the given socket registered"<<'\n';
            return true;

        }

        try{

            ClientInformation info( ip, socket );
            this->clientRegister.emplace_back(info);
            return true;

        }catch(const bad_alloc& e){

            verbose<<"--> [ClientRegister][addClient] Error, during memory allocation"<<'\n';
            return false;

        }

    }

    //  it removes a client basing on its socket
    bool ClientRegister::removeClient( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ){
                this->clientRegister.erase(this->clientRegister.begin()+a);
                return true;
            }

        return false;

    }

    string ClientRegister::getClientNetInformation(int socket){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ) {
                return this->clientRegister[a].getIPaddress();
            }
        return string();

    }

    bool ClientRegister::has( int socket ) {

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister[a].getSocket() == socket )
                return true;

        return false;

    }

}