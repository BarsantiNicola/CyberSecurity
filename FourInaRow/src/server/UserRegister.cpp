
#include "UserRegister.h"

namespace server{

    bool UserRegister::addUser( int socket , string username ){

        if( this->userRegister.size() == this->userRegister.max_size()){

            verbose<<"--> [UserRegister][addUser] Error, the register is full"<<'\n';
            return false;

        }

        if( this->has( username )){

            verbose<<"--> [UserRegister][addUser] Error, the user is already registered"<<'\n';
            return false;

        }

        UserInformation user( socket, username );

        try{

            this->userRegister.emplace_back( user );
            return true;

        }catch(const bad_alloc& e){

            verbose<<"-->[UserRegister][addUser] Error during memory allocation"<<'\n';
            return false;

        }

    }

    bool UserRegister::setSessionKey( string username , cipher::SessionKey* key ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setSessionKey( key );

        verbose<<"-->[UserRegister][setSessionKey] Error, user not found"<<'\n';
        return false;

    }

    bool UserRegister::setNonce( string username , int nonce ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username )) {
                cout<<"ok found"<<endl;
                this->userRegister[a].setNonce(nonce);
                cout<<"ok found2"<<endl;
                return true;

            }

        verbose<<"-->[UserRegister][setNonce] Error, user not found"<<'\n';
        return false;

    }

    bool UserRegister::setLogged( string username , cipher::SessionKey* key ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username )) {

                if( !this->userRegister[a].setStatus(LOGGED ))
                    return false;

                if( !this->userRegister[a].setSessionKey( key )){

                    this->userRegister[a].setStatus( CONNECTED );
                    return false;

                }

                return true;

            }

        verbose<<"-->[UserRegister][setLogged] Error, user not found"<<'\n';
        return false;

    }

    bool UserRegister::setPlay( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( PLAY );

        verbose<<"-->[UserRegister][setPlay] Error, user not found"<<'\n';
        return false;

    }

    bool UserRegister::setWait( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( WAIT_MATCH );

        verbose<<"-->[UserRegister][setWait] Error, user not found"<<'\n';
        return false;

    }

    bool UserRegister::setDisconnected( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( CONNECTED );

        verbose<<"-->[UserRegister][setDisconnected] Error, user not found"<<'\n';
        return false;

    }


    bool UserRegister::removeUser( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username )) {

                this->userRegister.erase(this->userRegister.begin() + a);
                return true;

            }

        verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
        return false;

    }

    bool UserRegister::removeUser( int socket ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket ) {

                this->userRegister.erase(this->userRegister.begin() + a);
                return true;

            }

        verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
        return false;

    }

    bool UserRegister::has( int socket ){


        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket )
                return true;

        verbose<<"-->[UserRegister][has] Error user not found"<<'\n';
        return false;

    }

    bool UserRegister::has( string username ){


        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return true;

        verbose<<"-->[UserRegister][has] Error user not found"<<'\n';
        return false;

    }

    cipher::SessionKey* UserRegister::getSessionKey( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getSessionKey();

        verbose<<"-->[UserRegister][getSessionKey] Error user not found"<<'\n';
        return nullptr;

    }


    int* UserRegister::getNonce( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getNonce();

        verbose<<"-->[UserRegister][getNonce] Error user not found"<<'\n';
        return nullptr;

    }

    string UserRegister::getUsername( int socket ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket )
                return this->userRegister[a].getUsername();

        verbose<<"-->[UserRegister][getUsername] Error user not found"<<'\n';
        return string();

    }

    UserStatus* UserRegister::getStatus( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getStatus();

        verbose<<"-->[UserRegister][getStatus] Error user not found"<<'\n';
        return nullptr;

    }

    NetMessage* UserRegister::getUserList(){
        string user_list = "USER LIST:\n";
        for( int a = 0; a<this->userRegister.size(); a++ )
            if( *(this->userRegister[a].getStatus()) != PLAY ) {
                user_list.append("\n\tusername: ");
                user_list.append(this->userRegister[a].getUsername());
            }
        return new NetMessage( (unsigned char*)user_list.c_str(), user_list.length());

    }


}