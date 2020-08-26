
#include "MainServer.h"


namespace server {

    Message* MainServer::certificateHandler(Message* message){

        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"-->[MainServer][certificateHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        Message* ret = new Message();
        ret->setNonce( *nonce );
        delete nonce;

        this->cipherServer.setServerCertificate(ret);
        return this->cipherServer.toSecureForm(CERTIFICATE, ret );

    }

    Message* MainServer::loginHandler( Message* message , string ip ) {

        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"-->[MainServer][loginHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        if( message->getUsername().empty() ){
            verbose<<"-->[MainServer][loginHandler] Error, invalid message. Missing username"<<'\n';
            return this->errorResponse("Invalid Message. Missing Username");
        }

        message = this->cipherServer.fromSecureForm( message, "" );

        if( !message ){
            verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
            return this->errorResponse("Error during security verification");
        }

        Message* response = new Message();
        response->setNonce(*nonce);
        delete nonce;
        if( this->userRegister.hasUser(message->getUsername())){
            verbose<<"-->[MainServer][loginHandler] Error, user already logged"<<'\n';
            return this->cipherServer.toSecureForm(LOGIN_FAIL, message );
        }
        this->userRegister.addUser(message->getUsername(), ip);
        this->userRegister.setNonce(message->getUsername(), *(message->getNonce()));
        return this->cipherServer.toSecureForm( LOGIN_OK , message );

    }

    Message* MainServer::userListHandler( Message* message  ) {

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][userListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        Message *response = new Message();
        response->setNonce(*nonce);
        NetMessage *user_list = this->userRegister.getUserList();
        response->setUserList(user_list->getMessage(), user_list->length());

        delete user_list;
        delete nonce;
        return this->cipherServer.toSecureForm(USER_LIST, message);

    }

    Message* MainServer::rankListHandler( Message* message  ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][rankListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        Message *response;
        response->setNonce(*nonce);
        string rank_list = SQLConnector::getRankList();
        response->setRankList((unsigned char*)rank_list.c_str(), rank_list.length());

        delete nonce;
        return this->cipherServer.toSecureForm(USER_LIST, message);

    }

    Message* MainServer::matchListHandler( Message* message  ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][matchListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        if( !this->userRegister.hasUser(message->getAdversary_1()) || !this->userRegister.hasUser(message->getAdversary_2())){
            verbose << "-->[MainServer][matchListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        Message *response;
        response->setNonce(*nonce);
        response->setAdversary_1(message->getAdversary_1());
        response->setAdversary_2(message->getAdversary_2());
        this->userRegister.setNonce(message->getAdversary_1(), *nonce );

        if( this->matchRegister.addMatch( message->getAdversary_1() , message->getAdversary_2(), *nonce) ){
            verbose << "-->[MainServer][matchListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->cipherServer.toSecureForm( utility::REJECT , response );
        }
        return this->cipherServer.toSecureForm( utility::ACCEPT , response );
    }

    Message* MainServer::acceptHandler( Message* message  ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        int* match = this->matchRegister.getMatchID(message->getAdversary_1());
        if( !match ){
            verbose << "-->[MainServer][acceptHandler] Error, closed match" << '\n';
            return this->errorResponse("Error, closed match by the challenger");
        }

        if( *nonce != *(this->matchRegister.getNonce(*match))){
            verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
            return this->errorResponse("Error during security verification");
        }

        if( !this->userRegister.hasUser(message->getAdversary_1())){
            verbose << "-->[MainServer][acceptHandler] Error, challenger disconnected" << '\n';
            return this->errorResponse("Error, challenger disconencted");
        }

        this->matchRegister.setAccepted(*match);
        Message *response;
        response->setNonce(*nonce);
        response->setAdversary_1(message->getAdversary_1());
        response->setAdversary_2(message->getAdversary_2());

        return this->cipherServer.toSecureForm( utility::ACCEPT , response );

    }

    Message* MainServer::rejectHandler( Message* message ){

            int *nonce = message->getNonce();
            if (!nonce) {
                verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
                return this->errorResponse("Invalid Message. Missing Nonce");
            }

            int* match = this->matchRegister.getMatchID(message->getAdversary_1());
            if( !match ){
                return nullptr;
            }

            if( *nonce != *(this->matchRegister.getNonce(*match))){
                verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
                return this->errorResponse("Error during security verification");
            }

            if( !this->userRegister.hasUser(message->getAdversary_1())){
                return nullptr;
            }

            this->matchRegister.setRejected(*match);
            Message *response;
            response->setNonce(*nonce);
            response->setAdversary_1(message->getAdversary_1());
            response->setAdversary_2(message->getAdversary_2());

            return this->cipherServer.toSecureForm( utility::REJECT , response );

    }

    Message* MainServer::keyExchangeHandler( Message* message , int matchID, string username ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        if( *nonce != *(this->matchRegister.getNonce(matchID))){
            verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
            return this->errorResponse("Error during security verification");
        }

        if( !message->getDHkeyLength()){
            verbose << "-->[MainServer][acceptHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';
            return this->errorResponse("Invalid Message.Missing Diffie-Hellman Parameter" );
        }

        this->userRegister.setLogged(username,*(this->cipherServer.getSessionKey(message)));
        return nullptr;

    }

    Message* MainServer::gameParamHandler(string source, int matchID, bool step ){

        Message* message = new Message();
        message->setNonce( *(this->matchRegister.getNonce(matchID)));
        string ip = this->userRegister.getIP(source);

        message->setNetInformations( (unsigned char*)ip.c_str(), ip.length());

        if( step )
            this->matchRegister.setStarted(matchID);
        else
            this->matchRegister.setLoaded(matchID);
        return this->cipherServer.toSecureForm(GAME_PARAM, message );

    }
    Message* MainServer::disconnectHandler( Message* message , int matchID ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }


        this->matchRegister.removeMatch(matchID);
        Message *response;
        response->setNonce(*nonce);

        return this->cipherServer.toSecureForm( utility::DISCONNECT, response );

    }

    Message* MainServer::closeMatch( int matchID ){

        Message *response;
        response->setNonce(this->matchRegister.getMatch(matchID)->getNonce());
        this->matchRegister.removeMatch(matchID);
        return this->cipherServer.toSecureForm(utility::REJECT, response );

    }

    Message* MainServer::logoutHandler( Message* message , string username ){

        int *nonce = message->getNonce();
        MatchInformation* info;
        vector<int> matches;
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->errorResponse("Invalid Message. Missing Nonce");
        }

        Message* response = new Message();
        response->setNonce(*(message->getNonce()));
        this->userRegister.removeUser(username);
        matches = this->matchRegister.getAllMatchID(username);
        for( int i : matches ) {
            info = this->matchRegister.getMatch(i);
            //  prelevare socket
            //  invio messaggio ricevuto
            this->closeMatch(i);
        }

        return this->cipherServer.toSecureForm(LOGOUT_OK, response );
    }

    Message* MainServer::errorResponse( string errorMessage ){return nullptr;}



    MainServer::MainServer( string ipAddr , int port ){}
    Message* MainServer::clientManager(Message* message, int socket ){ return nullptr; }
    Message* MainServer::userManager(Message* message, string username ){ return nullptr; }
    Message* MainServer::matchManager(Message* message, string username ){ return nullptr; }

}


int main() {
    MainServer* server = new MainServer( "127.0.0.1" , 12345 );

}
