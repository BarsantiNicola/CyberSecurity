
#include "ClientRegister.h"

namespace server{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  add a new client connection information to the register. If the information is already present
    //  it silently discard the request[socket MUST BE unique]
    bool ClientRegister::addClient( string ip , int socket ){

        if( this->clientRegister.size() == this->clientRegister.max_size() ){

            verbose<<"--> [ClientRegister][addClient] Error, the register is full"<<'\n';
            return false;

        }

        if( this->has( socket )) {

            vverbose<<"--> [ClientRegister][addClient] The register already has registered the socket: "<<socket<<'\n';
            return true;

        }

        try{

            ClientInformation info( ip, socket );
            this->clientRegister.emplace_back(info);
            vverbose<<"--> [ClientRegister][addClient] Client "<<socket<<" correctly added to the register"<<'\n';
            return true;

        }catch(const bad_alloc& e){

            verbose<<"--> [ClientRegister][addClient] Error, during memory allocation"<<'\n';
            return false;

        }

    }

    //  it removes a client searched by its socket
    bool ClientRegister::removeClient( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ){
                this->clientRegister.erase(this->clientRegister.begin()+a);
                vverbose<<"--> [ClientRegister][removeClient] Client removed from the client Register"<<'\n';
                return true;
            }

        vverbose<<"--> [ClientRegister][removeClient] Client not present into the register"<<'\n';
        return false;

    }

    //  it gives the ip address of a client searched by its socket
    string ClientRegister::getClientNetInformation( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket )
                return this->clientRegister[a].getIPaddress();

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return string();

    }

    int* ClientRegister::getNonce( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket )
                return this->clientRegister[a].getNonce();

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return nullptr;

    }

    int* ClientRegister::getClientNonce( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket )
                return this->clientRegister[a].getSendNonce();

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return nullptr;

    }

    int* ClientRegister::getClientReceiveNonce( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket )
                return this->clientRegister[a].getReceiveNonce();

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return nullptr;

    }

    bool ClientRegister::setNonce( int socket , int nonce ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ) {
                this->clientRegister[a].setNonce(nonce);
                return true;
            }

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return false;

    }

    bool ClientRegister::updateClientNonce( int socket ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ) {
                this->clientRegister[a].updateSendNonce();
                return true;
            }

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return false;

    }

    bool ClientRegister::updateClientReceiveNonce( int socket, int nonce ){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ) {
                this->clientRegister[a].updateReceiveNonce( nonce );
                return true;
            }

        vverbose<<"--> [ClientRegister][getClientNetInformation] Client not present into the register"<<'\n';
        return false;

    }

    bool ClientRegister::updateIp(int socket, int port){

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if( this->clientRegister[a].getSocket() == socket ) {
                this->clientRegister[a].updateIP(port);
                return true;
            }

        vverbose<<"--> [ClientRegister][updateIp] Client not present into the register"<<'\n';
        return false;

    }



    //  verify the presence of a client searched by its socket
    bool ClientRegister::has( int socket ) {

        for( int a = 0; a<this->clientRegister.size(); a++ )
            if (this->clientRegister[a].getSocket() == socket ) {
                vverbose<<"--> [ClientRegister][has] Client "<<socket<<" present"<<'\n';
                return true;
            }

        vverbose<<"--> [ClientRegister][has] Client "<<socket<<" not present"<<'\n';
        return false;

    }

}