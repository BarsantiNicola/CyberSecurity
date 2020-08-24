
#include "UserRegister.h"

namespace server{

    bool UserRegister::addUser( string username ){

        if( this->userRegister.size() == this->userRegister.max_size()){

            verbose<<"--> [UserRegister][addUser] Error, the register is full"<<'\n';
            return false;

        }

        if( this->getUserID(username)){

            verbose<<"--> [UserRegister][addUser] Error, the user is already registered"<<'\n';
            return false;

        }

        UserInformation user(username);

        try{

            this->userRegister.emplace_back( user );

        }catch(const bad_alloc& e){

            verbose<<"-->[UserRegister][addUser] Error bad allocation"<<'\n';
            return false;

        }
        return true;

    }

    bool UserRegister::removeUser( string username ){

        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.erase( this->userRegister.begin()+*pos);
        delete pos;
        return true;
    }

    UserInformation* UserRegister::getUser( string username ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return nullptr;

        }

        return new UserInformation( this->userRegister.at(*pos).getUsername() , this->userRegister.at(*pos).getStatus() , this->userRegister.at(*pos).getSessionKey());
    }

    bool UserRegister::hasUser( string username ){
        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister.at(a).getUsername().compare(username))
                return true;
        return false;

    }

    bool UserRegister::setLogged( string username , unsigned char* sessionKey , unsigned int len ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.at(*pos).setSessionKey( sessionKey, len );
        this->userRegister.at(*pos).setStatus( LOGGED );
        return true;
    }

    bool UserRegister::setPlay( string username ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.at(*pos).setStatus( PLAY );
        return true;
    }

    bool UserRegister::setWait( string username ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.at(*pos).setStatus( WAIT_MATCH );
        return true;
    }

    int* UserRegister::getUserID( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister.at(a).getUsername().compare(username))
                return new int(a);
        return nullptr;
    }

}