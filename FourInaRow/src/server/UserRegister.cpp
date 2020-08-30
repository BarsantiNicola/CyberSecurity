
#include "UserRegister.h"

namespace server{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the function inserts a user into the register if it isn't already present
    bool UserRegister::addUser( int socket , string username ){

        if( this->userRegister.size() == this->userRegister.max_size()){

            verbose<<"--> [UserRegister][addUser] Error, the register is full"<<'\n';
            return false;

        }

        if( this->has( username )){

            vverbose<<"--> [UserRegister][addUser] The user is already registered"<<'\n';
            return false;

        }

        UserInformation user( socket, username );

        try{

            this->userRegister.emplace_back( user );
            return true;

        }catch( const bad_alloc& e ){

            verbose<<"--> [UserRegister][addUser] Error during memory allocation"<<'\n';
            return false;

        }

    }

    //  removes a user from the user register searching it by its username
    bool UserRegister::removeUser( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username )) {

                this->userRegister.erase(this->userRegister.begin() + a);
                return true;

            }

        verbose<<"--> [UserRegister][removeUser] Error user not found"<<'\n';
        return false;

    }

    //  removes a user from the user register searching it by its socket
    bool UserRegister::removeUser( int socket ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket ) {

                this->userRegister.erase(this->userRegister.begin() + a);
                return true;

            }

        verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
        return false;

    }

    //  searches a user from the user register searching it by its username
    bool UserRegister::has( int socket ){


        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket )
                return true;

        vverbose<<"-->[UserRegister][has] Error user not found"<<'\n';
        return false;

    }

    //  searches a user from the user register searching it by its socket
    bool UserRegister::has( string username ){


        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return true;

        vverbose<<"-->[UserRegister][has] Error user not found"<<'\n';
        return false;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  sets the session key of a user searched by its username
    bool UserRegister::setSessionKey( string username , cipher::SessionKey* key ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setSessionKey( key );

        verbose<<"--> [UserRegister][setSessionKey] Error, user not found"<<'\n';
        return false;

    }

    //  sets the nonce of a user searched by its username
    bool UserRegister::setNonce( string username , int nonce ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username )) {
                this->userRegister[a].setNonce(nonce);
                return true;

            }

        verbose<<"--> [UserRegister][setNonce] Error, user not found"<<'\n';
        return false;

    }

    //  sets a user as logged into the application and set its elaborated session key
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

        verbose<<"--> [UserRegister][setLogged] Error, user not found"<<'\n';
        return false;

    }

    //  sets a user as playing a match
    bool UserRegister::setPlay( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( PLAY );

        verbose<<"--> [UserRegister][setPlay] Error, user not found"<<'\n';
        return false;

    }

    // sets a user as waiting a match it has sent, to be accepted by the challenged user
    bool UserRegister::setWait( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( WAIT_MATCH );

        verbose<<"--> [UserRegister][setWait] Error, user not found"<<'\n';
        return false;

    }

    //  sets a user to be logout by the application
    bool UserRegister::setDisconnected( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].setStatus( CONNECTED );

        verbose<<"--> [UserRegister][setDisconnected] Error, user not found"<<'\n';
        return false;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // gives the session key of a user searched by its username
    cipher::SessionKey* UserRegister::getSessionKey( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getSessionKey();

        vverbose<<"-->[UserRegister][getSessionKey] Error user not found"<<'\n';
        return nullptr;

    }

    //  gives the nonce of a user searched by its username
    int* UserRegister::getNonce( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getNonce();

        vverbose<<"-->[UserRegister][getNonce] Error user not found"<<'\n';
        return nullptr;

    }

    //  gives the username of a user searched by its socket
    string UserRegister::getUsername( int socket ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getSocket() == socket )
                return this->userRegister[a].getUsername();

        vverbose<<"-->[UserRegister][getUsername] Error user not found"<<'\n';
        return string();

    }

    //  gives the status of a user searched by its username
    UserStatus* UserRegister::getStatus( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister[a].getUsername().compare( username ))
                return this->userRegister[a].getStatus();

        vverbose<<"-->[UserRegister][getStatus] Error user not found"<<'\n';
        return nullptr;

    }

    //  gives a formatted list of all the available users excepts the one given as argument
    NetMessage* UserRegister::getUserList( string username ){
        string user_list = "USER LIST:\n";
        for( int a = 0; a<this->userRegister.size(); a++ )
            if( *(this->userRegister[a].getStatus()) != PLAY && this->userRegister[a].getUsername().compare(username) != 0 ) {
                user_list.append("\n\tusername: ");
                user_list.append(this->userRegister[a].getUsername());
            }
        return new NetMessage( (unsigned char*)user_list.c_str(), user_list.length());

    }


}