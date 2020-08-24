
#include "ClientRegister.h"

namespace server{

    bool ClientRegister::addClient( int clientID , string ip , int socket ){

        if( this->clientRegister.size() == this->clientRegister.max_size() ){

            verbose<<"--> [ClientRegister][addClient] Error, the register is full"<<'\n';
            return false;

        }

        if( this->hasID( clientID )) {

            verbose<<"--> [ClientRegister][addClient] Error, the register already has the given clientID registered"<<'\n';
            return false;

        }

        if( this->hasSocket( socket )) {

            verbose<<"--> [ClientRegister][addClient] Error, the register already has the given socket registered"<<'\n';
            return false;

        }
        ClientInformation info( clientID, ip, socket );
        try{

            this->clientRegister.emplace_back(info);

        }catch(const bad_alloc& e){

            verbose<<"-->[ClientRegister][addClient] Error bad allocation"<<'\n';
            return false;

        }
        return true;

    }

    bool ClientRegister::removeClientBySocket( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister.at(a).getSocket() == socket ){
                this->clientRegister.erase(this->clientRegister.begin()+a);
                return true;
            }

        return false;

    }

    bool ClientRegister::removeClientByID( int clientID ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister.at(a).getClientID() == clientID ){
                this->clientRegister.erase(this->clientRegister.begin()+a);
                return true;
            }

        return false;

    }

    ClientInformation* ClientRegister::getClientBySocket( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister.at(a).getSocket() == socket )
                return new ClientInformation( this->clientRegister.at(a).getClientID(), this->clientRegister.at(a).getIPaddress() , this->clientRegister.at(a).getSocket());

        return nullptr;

    }

    ClientInformation* ClientRegister::getClientByID( int clientID ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister.at(a).getClientID() == clientID )
                return new ClientInformation( this->clientRegister.at(a).getClientID(), this->clientRegister.at(a).getIPaddress() , this->clientRegister.at(a).getSocket());

        return nullptr;
    }

    bool ClientRegister::hasID( int clientID ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister.at(0 ).getClientID() == clientID)
                return true;

        return false;

    }

    bool ClientRegister::hasSocket(int socket) {

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister.at(0 ).getSocket() == socket )
                return true;

        return false;

    }

}