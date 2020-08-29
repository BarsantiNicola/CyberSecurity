
#include "MainServer.h"


namespace server {

    Message* MainServer::sendError( string errorMessage ){

        Message* response = new Message();
        response->setMessageType( ERROR );
        response->setNonce( 0 );  //  to be srand()
        response->setMessage( (unsigned char*)errorMessage.c_str() , errorMessage.length() );

        this->cipherServer.toSecureForm( response );
        return response;

    }

    Message* MainServer::certificateHandler( Message* message ){
        cout<<"_---------------------------------------------------"<<endl;
        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"-->[MainServer][certificateHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING USERNAME")  );
        }
        cout<<"_---------------------------------------------------"<<endl;
        Message* ret = new Message();
        NetMessage* param = this->cipherServer.getServerCertificate();

        if(! param ){
            verbose<<"-->[MainServer][certificateHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING USERNAME")  );
        }
        cout<<"_---------------------------------------------------"<<endl;
        ret->setNonce( *nonce );
        ret->setMessageType(CERTIFICATE );
        ret->setServer_Certificate( param->getMessage(), param->length());

        delete message;

        message = this->cipherServer.toSecureForm( ret );
        if( !message ){
            verbose << "-->[MainServer][acceptHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';
            delete ret;
            delete nonce;
            return this->sendError(string("MISSING USERNAME")  );
        }
        delete nonce;
        cout<<"TYPE: "<<ret->getMessageType()<<'\n';
       // NetMessage* prova = Converter::encodeMessage(ret->getMessageType(), *ret );
//        delete prova;
        return message;

    }

    Message* MainServer::loginHandler( Message* message , int socket ) {

        //////  verification of message consistence

        int* nonce = message->getNonce();
        Message* ret;

        if( !nonce ){
            verbose<<"-->[MainServer][loginHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING USERNAME") );
        }

        if( message->getUsername().empty() ){
            verbose<<"-->[MainServer][loginHandler] Error, invalid message. Missing username"<<'\n';
            return this->sendError(string("MISSING USERNAME") );
        }


        Message* response = new Message();
        ret = this->cipherServer.fromSecureForm( message, message->getUsername() );
        response->setNonce(*nonce);

        cout<<"---------------1----------"<<endl;
        if( !ret ){

            response->setMessageType( LOGIN_FAIL );
            verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
            message =  this->cipherServer.toSecureForm( response );

            return message;

        }

        //////
        cout<<"---------------2----------"<<endl;
        if( this->userRegister.has( ret->getUsername() )){         //  if a user is already logger login has to fail

            response->setMessageType( LOGIN_FAIL );
            verbose<<"-->[MainServer][loginHandler] Error, user already logged"<<'\n';
            message = this->cipherServer.toSecureForm( response );

            return message;

        }
        cout<<"---------------3----------"<<endl;
        cout<<"SOCKET: "<<socket<<endl;
        if( !this->userRegister.addUser( socket, message->getUsername() )){  // add user to register

            response->setMessageType( LOGIN_FAIL );
            verbose<<"-->[MainServer][loginHandler] Error, during user registration"<<'\n';
            message = this->cipherServer.toSecureForm( response );

            return message;

        }
        cout<<"USER: "<<this->userRegister.has( message->getUsername())<<endl;
        cout<<"USER: "<<this->userRegister.has( socket )<<endl;
        cout<<"---------------4----------"<<endl;
        if( !this->userRegister.setNonce(message->getUsername(), *nonce) ){ //  save nonce for key_exchange
            cout<<"errore"<<endl;
            delete nonce;
            this->userRegister.removeUser( socket );
            response->setMessageType( LOGIN_FAIL );
            verbose<<"-->[MainServer][loginHandler] Error, during user registration"<<'\n';
            message = this->cipherServer.toSecureForm( response );

            return message;

        }

        cout<<"---------------5----------"<<endl;
        vverbose<<"-->[MainServer][loginHandler] "<<message->getUsername()<<" registration correctly started"<<'\n';
        response->setMessageType( LOGIN_OK );
        message = this->cipherServer.toSecureForm( response );
        delete ret;
        if( !message ){
            verbose << "-->[MainServer][loginHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';
            delete response;
            return this->sendError(string("MISSING USERNAME")  );
        }
        cout<<"---------------6----------"<<endl;
        cout<<"type: "<<message->getMessageType()<<endl;
        cout<<"nonce: "<<message->getNonce()<<endl;
     //   cout<<"USER: "<<this->userRegister.has( message->getUsername())<<endl;
        cout<<"USER: "<<this->userRegister.has( socket )<<endl;
        return message;

    }

    Message* MainServer::keyExchangeHandler( Message* message , string username ){

        int *nonce = message->getNonce();
        int *userNonce = this->userRegister.getNonce(username);

        if ( !nonce ){

            verbose << "-->[MainServer][keyExchangeHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError(string("MISSING_NONCE") );

        }

        if ( !userNonce ){

            verbose << "-->[MainServer][keyExchangeHandler] Error, user nonce not present" << '\n';
                return this->sendError(string("MISSION_NONCE") );

        }

        if( *nonce != *userNonce ){
            verbose<<"-->[MainServer][keyExchangeHandler] Error invalid nonce"<<'\n';
            return this->sendError(string("INVALID_NONCE") );
        }

        Message* result = this->cipherServer.fromSecureForm( message, username );

        if( !result->getDHkey() ){
            verbose << "-->[MainServer][keyExchangeHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';
            return this->sendError(string("MISSING_DHPARAM")  );
        }


        NetMessage* param = this->cipherServer.getPartialKey();
        Message* response = new Message();
        response->setMessageType( KEY_EXCHANGE );
        response->setNonce( *nonce );
        delete nonce;

        response->set_DH_key( param->getMessage(), param->length() );
        delete param;

        this->userRegister.setLogged( username , this->cipherServer.getSessionKey( result->getDHkey() , result->getDHkeyLength()));

        message = this->cipherServer.toSecureForm( response );

        if( !message ){
            verbose << "-->[MainServer][keyExchangeHandler] Error, during message convertion" << '\n';
            delete result;
            return this->sendError(string("MISSING USERNAME") );
        }

        return message;

    }

    Message* MainServer::userListHandler( Message* message  , string username ) {

        //////  verification of message consistence

        int* nonce = message->getNonce();

        if( !nonce ){
            verbose<<"-->[MainServer][userListHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING USERNAME")  );
        }

        Message* ret = this->cipherServer.fromSecureForm( message, message->getUsername() );

        if( !ret ){

            verbose<<"-->[MainServer][userListHandler] Error. Verification Failure"<<'\n';
            return this->sendError( string("MISSING USERNAME")  );

        }

        //////

        if( !this->userRegister.has( username )){
            verbose << "-->[MainServer][rankListHandler] Error, user not registered" << '\n';
            return this->sendError(string("MISSING USERNAME") );
        }

        if( *(this->userRegister.getStatus(username)) != LOGGED ){
            verbose << "-->[MainServer][rankListHandler] Error, user not allowed" << '\n';
            return this->sendError(string("MISSING USERNAME") );
        }

        Message* response = new Message();
        NetMessage *user_list = this->userRegister.getUserList();

        response->setMessageType( USER_LIST );
        response->setNonce( *nonce );
        response->setUserList( user_list->getMessage(), user_list->length() );

        delete user_list;
        delete nonce;

        message = this->cipherServer.toSecureForm(response );

        if( !message ){
            verbose << "-->[MainServer][userListHandler] Error during securing of message" << '\n';
            delete response;
            return this->sendError(string("MISSING USERNAME")  );
        }

        return message;

    }

    Message* MainServer::rankListHandler( Message* message  , string username ){


        //////  verification of message consistence

        int* nonce = message->getNonce();

        if( !nonce ){
            verbose<<"-->[MainServer][rankListHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("INVALID_NONCE") );
        }

        Message* ret = this->cipherServer.fromSecureForm( message, message->getUsername() );


        if( !ret ){

            verbose<<"-->[MainServer][rankListHandler] Error. Verification Failure"<<'\n';
            return this->sendError( string("MISSING USERNAME") );

        }


        //////

        if( !this->userRegister.has( username )){
            verbose << "-->[MainServer][rankListHandler] Error, user not registered" << '\n';
            return this->sendError(string("MISSING USERNAME") );
        }

        if( *(this->userRegister.getStatus(username)) != LOGGED ){
            verbose << "-->[MainServer][rankListHandler] Error, user not allowed" << '\n';
            return this->sendError(string("MISSING USERNAME") );
        }

        Message* response = new Message();
        string rank_list = SQLConnector::getRankList();

        response->setMessageType( RANK_LIST );
        response->setNonce( *nonce );
        response->setRankList( (unsigned char*) rank_list.c_str(), rank_list.length() );

        delete nonce;

        message = this->cipherServer.toSecureForm(response );
        if( !message ){
            verbose << "-->[MainServer][rankListHandler] Error. Verification Failure"<< '\n';
            delete response;
            return this->sendError(string("MISSING USERNAME")  );
        }


        return message;

    }



    Message* MainServer::logoutHandler( Message* message , string username ){

        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][logoutHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError(string("MISSING_NONCE") );
        }

        Message* response = this->cipherServer.fromSecureForm( message , username );

        if( !response ){
            verbose << "-->[MainServer][logoutHandler] Error, Verification failure" << '\n';
            return this->sendError(string("AUTH_FAIL") );
        }

        if( !this->userRegister.has( username )){
            verbose << "-->[MainServer][logoutHandler] Error user not registered" << '\n';
            return this->sendError(string("MISSING USERNAME") );
        }

        if( *(this->userRegister.getStatus(username)) != LOGGED ){
            verbose << "-->[MainServer][logoutHandler] Error, user not in the correct state" << '\n';
            return this->sendError(string("NOT_LOGGED") );
        }

        Message* ret = new Message();
        ret->setMessageType(LOGOUT_OK );
        ret->setNonce(*nonce);
        delete nonce;

        this->userRegister.removeUser(username);
        /*
        matches = this->matchRegister.getAllMatchID(username);
        for( int i : matches ) {
            info = this->matchRegister.getMatch(i);
            //  prelevare socket
            //  invio messaggio ricevuto
            this->closeMatch(i);
        }*/
        message = this->cipherServer.toSecureForm(ret);
        return message;

    }

    Message* MainServer::matchListHandler( Message* message  ){
/*
        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][matchListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError("Invalid Message. Missing Nonce");
        }

        if( !this->userRegister.hasUser(message->getAdversary_1()) || !this->userRegister.hasUser(message->getAdversary_2())){
            verbose << "-->[MainServer][matchListHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError("Invalid Message. Missing Nonce");
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
        return this->cipherServer.toSecureForm( utility::ACCEPT , response );*/
        return nullptr;
    }

    Message* MainServer::acceptHandler( Message* message  ){
/*
        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError("Invalid Message. Missing Nonce");
        }

        int* match = this->matchRegister.getMatchID(message->getAdversary_1());
        if( !match ){
            verbose << "-->[MainServer][acceptHandler] Error, closed match" << '\n';
            return this->sendError("Error, closed match by the challenger");
        }

        if( *nonce != *(this->matchRegister.getNonce(*match))){
            verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
            return this->sendError("Error during security verification");
        }

        if( !this->userRegister.hasUser(message->getAdversary_1())){
            verbose << "-->[MainServer][acceptHandler] Error, challenger disconnected" << '\n';
            return this->sendError("Error, challenger disconencted");
        }

        this->matchRegister.setAccepted(*match);
        Message *response;
        response->setNonce(*nonce);
        response->setAdversary_1(message->getAdversary_1());
        response->setAdversary_2(message->getAdversary_2());

        return this->cipherServer.toSecureForm( utility::ACCEPT , response );
*/
return nullptr;
    }

    Message* MainServer::rejectHandler( Message* message ){
/*
            int *nonce = message->getNonce();
            if (!nonce) {
                verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
                return this->sendError("Invalid Message. Missing Nonce");
            }

            int* match = this->matchRegister.getMatchID(message->getAdversary_1());
            if( !match ){
                return nullptr;
            }

            if( *nonce != *(this->matchRegister.getNonce(*match))){
                verbose<<"-->[MainServer][loginHandler] Error during security verification"<<'\n';
                return this->sendError("Error during security verification");
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

*/
return nullptr;
    }


    Message* MainServer::gameParamHandler(string source, int matchID, bool step ){
/*
        Message* message = new Message();
        message->setNonce( *(this->matchRegister.getNonce(matchID)));
        string ip = this->userRegister.getIP(source);

        message->setNetInformations( (unsigned char*)ip.c_str(), ip.length());

        if( step )
            this->matchRegister.setStarted(matchID);
        else
            this->matchRegister.setLoaded(matchID);
        return this->cipherServer.toSecureForm(GAME_PARAM, message );*/
        return nullptr;

    }
    Message* MainServer::disconnectHandler( Message* message , int matchID ){
/*
        int *nonce = message->getNonce();
        if (!nonce) {
            verbose << "-->[MainServer][acceptHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError("Invalid Message. Missing Nonce");
        }


        this->matchRegister.removeMatch(matchID);
        Message *response;
        response->setNonce(*nonce);

        return this->cipherServer.toSecureForm( utility::DISCONNECT, response );*/
        return nullptr;

    }

    Message* MainServer::closeMatch( int matchID ){
        /*
        Message *response;
        response->setNonce(this->matchRegister.getMatch(matchID)->getNonce());
        this->matchRegister.removeMatch(matchID);
        return this->cipherServer.toSecureForm(utility::REJECT, response );*/
        return nullptr;

    }



    MainServer::MainServer( string ipAddr , int port ){

        this->manager = new utility::ConnectionManager( true , ipAddr.c_str(), port );


    }


    Message* MainServer::userManager(Message* message, string username , int socket ) {

        Message* ret;
        switch( message->getMessageType() ){

            case utility::CERTIFICATE_REQ:
                ret = this->certificateHandler(message);
                break;
            case utility::LOGIN_REQ:
                ret = this->loginHandler(message, socket );
                break;
            case utility::KEY_EXCHANGE:
                ret = this->keyExchangeHandler(message, username );
                break;
            case utility::USER_LIST_REQ:
                ret = this->userListHandler(message, username );
                break;
            case utility::RANK_LIST_REQ:
                ret = this->rankListHandler(message, username );
                break;
            case utility::LOGOUT_REQ:
                ret = this->logoutHandler(message, username);
                break;
            case utility::MATCH:case utility::ACCEPT:case utility::REJECT:case utility::DISCONNECT:
                ret = this->matchManager( message , username );
            default:
                verbose<<"-->[MainServer][userManager] Error unknow message type: "<<message->getMessageType()<<'\n';
                return nullptr;
        }
        cout<<"type: "<<ret->getMessageType()<<endl;
        cout<<"nonce: "<<ret->getNonce()<<endl;
        return ret;

    }

    Message* MainServer::matchManager(Message* message, string username ){

        return nullptr;
    }

    void MainServer::server() {

        Message *message;
        Message *response;
        int socket;
        string username;
        string ipAddr;
        vector<int> waitSockets;

        if( !this->manager ){
            verbose<<"--> [MainServer][server] Fatal error, unable to find connectionManager"<<'\n';
            return;
        }

        while( true ){

            cout<<"restart"<<endl;
            socket = -1;
            ipAddr.clear();
            waitSockets.clear();
            cout<<"start waiting"<<endl;
            waitSockets = this->manager->waitForMessage( &socket, &ipAddr );
            cout<<"ok finish"<<endl;
            if( !waitSockets.size() ){

                if( socket != -1 && !ipAddr.empty()){

                    vverbose<<"--> [MainServer][server] New client connection received: "<<socket<<'\n';
                    this->clientRegister.addClient( ipAddr, socket );
                    continue;
                }

                verbose<<"--> [MainServer][server] Error into connection management"<<'\n';
                continue;

            }

            for( int sock : waitSockets ){
                if( sock == -1 ) continue;
                try {
                    message = this->manager->getMessage(sock);
                }catch( runtime_error){
                    vverbose<<"--> [MainServer][server] Client "<<socket<<" disconnected"<<'\n';
                    //  remove from match
                    this->userRegister.removeUser( socket );
                    this->clientRegister.removeClient( socket );
                    continue;
                }
                if( message ) {

                    vverbose << "--> [MainServer][server] New message(" << message->getMessageType()
                             << ") received from client: " << sock << '\n';

                    response = this->manageMessage(message, sock);
                    cout << "OKOK" << endl;
                    cout << response->getMessageType() << "  " << *(response->getNonce()) << endl;
                    //   NetMessage* prova = Converter::encodeMessage(response->getMessageType(), *response );
                    bool socketClosed = false;
                    if (response) {
                        cout<<"ok"<<endl;
                        if (!this->manager->sendMessage(*response, sock, &socketClosed, nullptr, 0) && socketClosed) {
                            vverbose << "--> [MainServer][server] Error, client " << socket << " disconnected" << '\n';
                            delete response;
                            this->userRegister.removeUser(socket);
                            this->clientRegister.removeClient(socket);
                        }
                        cout<<"okok"<<endl;
                    }
                }
            }
        }
    }

    Message* MainServer::manageMessage( Message* message, int socket ){

        //  verify the user is not already registered
        if (!this->clientRegister.has(socket)) {
            verbose << "-->[MainServer][manageMessage] Error, unregistered socket try to contact server" << '\n';
            return sendError(string("UNREGISTERED_SOCK"));
        }

        if (!this->userRegister.has(socket) && message->getMessageType() != LOGIN_REQ && message->getMessageType() != CERTIFICATE_REQ ) {

            vverbose << "-->[MainServer][manageMessage] Warning, user not already logged. Invalid request" << '\n';
            return sendError(string("INVALID_REQUEST"));

        }

        string username = this->userRegister.getUsername(socket);
        if (username.empty() && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ) {

            vverbose << "-->[MainServer][manageMessage] Error, username not found" << '\n';
            return sendError(string("USER_NOT_FOUND"));

        }

        return this->userManager(message, username, socket);


    }


}
int main() {

    Logger::setThreshold( VERY_VERBOSE );
    MainServer* server = new MainServer( string("127.0.0.1") , 12345 );
    server->server();
    return 0;


}




