
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

    void UserRegister::test(){

        UserRegister *reg = new UserRegister();
        if( !reg->addUser("marco")) {
            base << "Error1" << '\n';
            return;
        }
        if( !reg->addUser("nicola")) {
            base << "Error2" << '\n';
            return;
        }
        if( !reg->addUser("alessia")) {
            base << "Error3" << '\n';
            return;
        }
        if( reg->addUser("marco")){
            base<<"Error4"<<'\n';
            return;
        }
        if( reg->addUser("nicola")){
            base<<"Error5"<<'\n';
            return;
        }
        if( !reg->removeUser("nicola")){
            base<<"Error6"<<'\n';
            return;
        }
        if( reg->removeUser("nicola")){
            base<<"Error7"<<'\n';
            return;
        }
        if( reg->removeUser("luca")){
            base<<"Error8"<<'\n';
            return;
        }
        if( !reg->hasUser("marco")){
            base<<"Error9"<<'\n';
            return;
        }
        if( reg->hasUser("nicola")){
            base<<"Error10"<<'\n';
            return;
        }
        if( !reg->hasUser("alessia")){
            base<<"Error11"<<'\n';
            return;
        }
        if( reg->hasUser("luca")){
            base<<"Error12"<<'\n';
            return;
        }
        if( reg->hasUser("lucia")){
            base<<"Error13"<<'\n';
            return;
        }
        if( reg->getUserID("marco") == nullptr ){
            base<<"Error14"<<'\n';
            return;
        }
        if( reg->getUserID("lucia") != nullptr ){
            base<<"Error15"<<'\n';
            return;
        }
        if( !reg->setLogged("marco",(unsigned char*)"123124",6 )){
            base<<"Error16"<<'\n';
            return;
        }
        if( reg->setLogged("jonni",(unsigned char*)"123124",6 )){
            base<<"Error17"<<'\n';
            return;
        }
        if( !reg->setWait("marco")){
            base<<"Error18"<<'\n';
            return;
        }
        if( !reg->setWait("alessia")){
            base<<"Error19"<<'\n';
            return;
        }
        if( !reg->setLogged("alessia",(unsigned char*)"123124",6 )){
            base<<"Error20"<<'\n';
            return;
        }
        if( !reg->setPlay("marco")){
            base<<"Error21"<<'\n';
            return;
        }
        if( !reg->setPlay("alessia")){
            base<<"Error22"<<'\n';
            return;
        }
        UserInformation* user = reg->getUser("marco");
        if( !user || user->getUsername().compare("marco")!=0 || user->getStatus() != PLAY ){
            base<<"Error23"<<'\n';
            return;
        }
        delete user;
        if( reg->getUser("luca")) {
            base << "Error24" << '\n';
            return;
        }
        verbose<<"Success"<<'\n';


    }

}