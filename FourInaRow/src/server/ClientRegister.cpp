
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
            if( this->clientRegister.at(a).getSocket() == socket ) {
                ClientInformation *client = new ClientInformation(this->clientRegister.at(a).getClientID(),
                                                                  this->clientRegister.at(a).getIPaddress(),
                                                                  this->clientRegister.at(a).getSocket());
                return client;
            }
        return nullptr;

    }

    ClientInformation* ClientRegister::getClientByID( int clientID ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister.at(a).getClientID() == clientID ) {
                ClientInformation *client = new ClientInformation(this->clientRegister.at(a).getClientID(),
                                                                  this->clientRegister.at(a).getIPaddress(),
                                                                  this->clientRegister.at(a).getSocket());
                return client;
            }
        return nullptr;
    }

    bool ClientRegister::hasID( int clientID ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister.at(a ).getClientID() == clientID)
                return true;

        return false;

    }

    bool ClientRegister::hasSocket(int socket) {

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister.at(a ).getSocket() == socket )
                return true;

        return false;

    }



    void ClientRegister::test(){
        base<<"------------------ CLIENT INFORMATION TEST ------------------"<<'\n';

        ClientRegister* reg = new ClientRegister();

        if( !reg->addClient( 1 , "127.0.0.1", 10000) )  //  TRUE
            base<<"Error 1"<<'\n';
        if( !reg->addClient( 10 , "127.0.0.1", 10300) ) //  TRUE
            base<<"Error 2"<<'\n';
        if( !reg->addClient( 2 , "127.0.0.1", 10400) )  //  TRUE
            base<<"Error 3"<<'\n';
        if( reg->addClient( 1 , "127.0.0.1", 1000) )   // FALSE DUPLICATE CLIENT_ID
            base<<"Error 4"<<'\n';
        if( reg->addClient( 11 , "127.0.0.1", 10000) )  //  FALSE DUPLICATE SOCKET
            base<<"Error 5"<<'\n';

        if( reg->removeClientBySocket(9000) )    //  FALSE UNKNOWN ID
            base<<"Error 6"<<'\n';
        if( !reg->removeClientBySocket(10000) )  //  TRUE
            base<<"Error 7"<<'\n';
        if( !reg->addClient( 1 , "127.0.0.1",  10000) )  //TRUE
            base<<"Error 8"<<'\n';
        if( !reg->removeClientByID(1) )   //  TRUE
            base<<"Error 9"<<'\n';
        if( reg->removeClientByID(1) )  //  FALSE UNKNOWN ID
            base<<"Error 10"<<'\n';
        if( reg->hasID(1))    // FALSE UNKNOWN ID
            base<<"Error 11"<<'\n';
        if( reg->hasID(11))   //  FALSE UNKNOWN ID
            base<<"Error 12"<<'\n';
        if( !reg->hasSocket(10300))  // TRUE
            base<<"Error 13"<<'\n';
        if( reg->hasSocket(10000))  // FALSE UNKNOWN ID
            base<<"Error 14"<<'\n';
        ClientInformation * client = reg->getClientBySocket( 10300 );
        if( !client || client->getClientID() != 10 || client->getIPaddress().compare("127.0.0.1") != 0 || client->getSocket() != 10300 )
            base<<"Error 15"<<'\n';
        delete client;
        client = reg->getClientByID(2 );
        if( !client || client->getClientID() != 2 || client->getIPaddress().compare("127.0.0.1") != 0 || client->getSocket() != 10400 )
            base<<"Error 16"<<'\n';
        delete client;
        client = reg->getClientByID(14);
        if( client )
            base<<"Error 17"<<'\n';
        delete client;
        if( reg->getClientBySocket(10000))
            base<<"Error 18"<<'\n';
        verbose<<"Success"<<'\n';
    }

}