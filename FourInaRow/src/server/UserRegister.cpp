
#include "UserRegister.h"

namespace server{

    bool UserRegister::addUser( string username , string ip ){

        if( this->userRegister.size() == this->userRegister.max_size()){

            verbose<<"--> [UserRegister][addUser] Error, the register is full"<<'\n';
            return false;

        }

        if( this->getUserID(username)){

            verbose<<"--> [UserRegister][addUser] Error, the user is already registered"<<'\n';
            return false;

        }

        UserInformation user(username, ip);

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

        UserInformation* user = new UserInformation( this->userRegister.at(*pos).getUsername() , this->userRegister.at(*pos).getStatus() , this->userRegister.at(*pos).getIP(), this->userRegister.at(*pos).getSessionKey());
        if( this->userRegister[*pos].getNonce() )
            user->setNonce(*(this->userRegister[*pos].getNonce()));
        return user;
    }

    bool UserRegister::hasUser( string username ){
        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister.at(a).getUsername().compare(username))
                return true;
        return false;

    }

    bool UserRegister::setLogged( string username , cipher::SessionKey key ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.at(*pos).setSessionKey( key );
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

    bool UserRegister::setNonce( string username, int nonce ){
        int* pos = getUserID(username);
        if( !pos ){

            verbose<<"-->[UserRegister][removeUser] Error user not found"<<'\n';
            return false;

        }
        this->userRegister.at(*pos).setNonce( nonce );
        return true;
    }

    int* UserRegister::getNonce( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister.at(a).getUsername().compare(username))
                return new int(*(this->userRegister[a].getNonce()));
        return nullptr;
    }

    int* UserRegister::getUserID( string username ){

        for( int a = 0; a<this->userRegister.size(); a++ )
            if( !this->userRegister.at(a).getUsername().compare(username))
                return new int(a);
        return nullptr;
    }

    NetMessage* UserRegister::getUserList(){
        string user_list = "USER LIST:\n";
        for( int a = 0; a<this->userRegister.size(); a++ )
            if( this->userRegister[a].getStatus() != PLAY ) {
                user_list.append("\n\tusername: ");
                user_list.append(this->userRegister[a].getUsername());
            }
        return new NetMessage( (unsigned char*)user_list.c_str(), user_list.length());

    }

    string UserRegister::getIP(string username){

        UserInformation* user = this->getUser(username);
        if( !user ){
            return "";
        }
        string ip = user->getIP();
        delete user;
        return ip;

    }

    void UserRegister::test(){

        UserRegister *reg = new UserRegister();
        if( !reg->addUser("marco","127.0.0.1")) {
            base << "Error1" << '\n';
            return;
        }
        if( !reg->addUser("nicola","127.0.0.1")) {
            base << "Error2" << '\n';
            return;
        }
        if( !reg->addUser("alessia","127.0.0.1")) {
            base << "Error3" << '\n';
            return;
        }
        if( reg->addUser("marco","127.0.0.1")){
            base<<"Error4"<<'\n';
            return;
        }
        if( reg->addUser("nicola","127.0.0.1")){
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
        cipher::SessionKey key;
        if( !reg->setLogged("marco",key)){
            base<<"Error16"<<'\n';
            return;
        }

        if( reg->setLogged("jonni",key )){
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
        if( !reg->setLogged("alessia",key)){
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