
#include "MainServer.h"


namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    MainServer::MainServer( string ipAddr , int port ){

        this->manager = new utility::ConnectionManager( true , ipAddr.c_str(), port );

    }

    //  starts the server. The function doesn't return. It will continue until a fatal error happens or the user manually close
    //  the program by Control-C
    void MainServer::server() {

        Message *message;
        Message *response;
        int socket;
        string ipAddr;
        vector<int> waitSockets;

        if( !this->manager ){
            verbose<<"--> [MainServer][server] Fatal error, unable to find connectionManager"<<'\n';
            return;
        }

        while( true ){

            socket = -1;
            ipAddr.clear();
            waitSockets.clear();

            vverbose<<"--> [MainServer][server] Server waiting to receive a message"<<'\n';
            waitSockets = this->manager->waitForMessage( &socket, &ipAddr );


            if( socket != -1 && !ipAddr.empty() ){

                vverbose<<"--> [MainServer][server] New client connection received: "<<socket<<'\n';
                this->clientRegister.addClient( ipAddr, socket );
                continue;

            }

            if( !waitSockets.size() ){
                verbose<<"--> [MainServer][server] Error into connection management"<<'\n';
                continue;

            }

            for( int sock : waitSockets ){

                if( sock == -1 ) continue;

                try {

                    message = this->manager->getMessage( sock );

                }catch( runtime_error ){

                    vverbose<<"--> [MainServer][server] Client "<<sock<<" disconnected"<<'\n';
                    this->logoutClient( sock );
                    continue;

                }

                if( message ) {

                    vverbose << "--> [MainServer][server] New message(" << message->getMessageType()<< ") received from client: " << sock << '\n';

                    response = this->manageMessage( message, sock );
                    delete message;

                    bool socketClosed = false;

                    if (response) {

                        if (!this->manager->sendMessage(*response, sock, &socketClosed, nullptr, 0) && socketClosed) {

                            vverbose << "--> [MainServer][server] Error, unable to send message, client " << socket << " disconnected" << '\n';

                            vector<int> matches = this->matchRegister.getAllMatchID( this->userRegister.getUsername(sock));
                            for( int matchID: matches )
                                this->closeMatch( matchID );

                            this->userRegister.removeUser(socket);
                            this->clientRegister.removeClient(socket);
                        }
                    }

                    delete response;

                }
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      MESSAGE HANDLERS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the function verify the message consistency then it will pass it to the correct handler
    Message* MainServer::manageMessage( Message* message, int socket ){

        //  verify the user is not already registered
        if ( !this->clientRegister.has(socket) ) {

            verbose << "--> [MainServer][manageMessage] Error, unregistered socket tried to contact the server" << '\n';
            return sendError(string( "UNREGISTERED_SOCK" ), message->getNonce());

        }

        if (!this->userRegister.has(socket) && message->getMessageType() != LOGIN_REQ && message->getMessageType() != CERTIFICATE_REQ ) {

            vverbose << "--> [MainServer][manageMessage] Warning, user not already logged. Invalid request" << '\n';
            return sendError(string( "INVALID_REQUEST"), message->getNonce());

        }

        string username = this->userRegister.getUsername(socket);
        if (username.empty() && message->getMessageType() != CERTIFICATE_REQ && message->getMessageType() != LOGIN_REQ ) {

            vverbose << "--> [MainServer][manageMessage] Error, username not found" << '\n';
            return sendError(string( "USER_NOT_FOUND" ), message->getNonce());

        }

        return this->userManager( message, username, socket );

    }

    //  the function manages the messages which involve only him and the contacted server(no other clients have to be contacted)
    //  if the function has not the authority to manage the message it passes it to the matchManager to manage it
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
            default:
                ret = this->matchManager( message , username );
        }

        return ret;

    }

    Message* MainServer::matchManager(Message* message, string username ){

        return nullptr;
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                        EVENT HANDLERS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    void MainServer::logoutClient( int socket ) {
        //  remove from match
        this->userRegister.removeUser( socket );
        this->clientRegister.removeClient( socket );

    }

    bool MainServer::closeMatch( int matchID ){
        /*
        Message *response;
        response->setNonce(this->matchRegister.getMatch(matchID)->getNonce());
        this->matchRegister.removeMatch(matchID);
        return this->cipherServer.toSecureForm(utility::REJECT, response );*/
        return true;

    }

    Message* MainServer::sendError( string errorMessage, int* nonce ){

        vverbose<<"--> [MainServer][sendError] Generation of error message: "<<errorMessage<<'\n';

        Message* response = new Message();
        response->setMessageType( ERROR );
        if( !nonce ) {
            srand(time(nullptr));
            response->setNonce(rand());
        }else
            response->setNonce(*nonce);
        response->setMessage( (unsigned char*)errorMessage.c_str() , errorMessage.length() );

        this->cipherServer.toSecureForm( response );
        return response;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PROTOCOL HANDLERS                                    //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////


    //  the handler manages the CERTIFICATE_REQ requests by generating a formatted message containing the server certificate
    Message* MainServer::certificateHandler( Message* message ){

        //  verification of message consistency
        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"--> [MainServer][certificateHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING_NONCE"), nonce );
        }

        //  preparation of response message
        NetMessage* param = this->cipherServer.getServerCertificate();

        if(! param ){
            verbose<<"--> [MainServer][certificateHandler] Error, unable to load server certificate"<<'\n';
            return this->sendError( string("SERVER_ERROR"), nonce );
        }

        Message* result = new Message();
        result->setNonce( *nonce );
        result->setMessageType(CERTIFICATE );
        result->setServer_Certificate( param->getMessage(), param->length());
        delete param;

        if( !this->cipherServer.toSecureForm( result )){
            verbose << "--> [MainServer][certificateHandler] Error, message didn't pass security verification" << '\n';
            delete result;
            result = this->sendError(string("SECURITY_ERROR"), nonce );
        }else
            vverbose<<"--> [MainServer][certificateHandler] CERTIFICATE message correctly generated"<<'\n';

        delete nonce;

        return result;

    }

    //  the handler manages the LOGIN_REQ requests verifying if the user is already registered and its signature is valid
    Message* MainServer::loginHandler( Message* message , int socket ){

        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"--> [MainServer][loginHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string("MISSING_NONCE"), nonce );
        }

        if( message->getUsername().empty() ){
            verbose<<"--> [MainServer][loginHandler] Error, invalid message. Missing username"<<'\n';
            return this->sendError(string("MISSING_USERNAME"), nonce );
        }

        Message* response = new Message();
        response->setNonce(*nonce);


        if( !this->cipherServer.fromSecureForm( message , message->getUsername() )){

            verbose<<"--> [MainServer][loginHandler] Error during security verification"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response );

            delete nonce;
            return response;

        }

        vverbose<<"--> [MainServer][loginHandler] Message has passed validation check"<<'\n';

        if( this->userRegister.has( message->getUsername() )){  //  if a user is already logger login has to fail

            verbose<<"--> [MainServer][loginHandler] Error, user already logged"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response );

            delete nonce;
            return response;

        }

        if( !this->userRegister.addUser( socket, message->getUsername() )){  // add user to register

            verbose<<"--> [MainServer][loginHandler] Error, during user registration"<<'\n';
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response );

            delete nonce;
            return response;

        }

        if( !this->userRegister.setNonce(message->getUsername(), *nonce) ){    //  save nonce for key_exchange

            verbose<<"-->[MainServer][loginHandler] Error, during the setting of user nonce"<<'\n';
            this->userRegister.removeUser( socket );
            response->setMessageType( LOGIN_FAIL );
            this->cipherServer.toSecureForm( response );

            delete nonce;
            return response;

        }

        response->setMessageType( LOGIN_OK );

        if( !this->cipherServer.toSecureForm( response )){
            verbose << "-->[MainServer][loginHandler] Error, invalid message Missing Diffie-Hellman Parameter" << '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    //  the handler manages the KEY_EXCHANGE requests. After has verified the user is correctly registered and the used nonce is the
    //  same of the user login, the service sends a diffie-hellman parameter to the client and combining it with
    //  the received param generates the values necessary to create a secure net-channel
    Message* MainServer::keyExchangeHandler( Message* message , string username ){

        int *nonce = message->getNonce();

        if ( !nonce ){

            verbose << "--> [MainServer][keyExchangeHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError(string("MISSING_NONCE"), nonce );

        }

        Message* response;
        int *userNonce = this->userRegister.getNonce(username);

        if ( !userNonce ){

            verbose << "--> [MainServer][keyExchangeHandler] Error, user nonce not present" << '\n';
            response = this->sendError(string("SERVER_ERROR"), nonce );

            delete nonce;
            return response;

        }

        if( *nonce != *userNonce ){

            verbose<<"--> [MainServer][keyExchangeHandler] Error invalid nonce"<<'\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            delete userNonce;
            return response;

        }

        delete userNonce;

        if( !this->cipherServer.fromSecureForm( message, username )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, message didn't pass the security checks" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][keyExchangeHandler] Request has passed security checks" << '\n';

        NetMessage* param = this->cipherServer.getPartialKey();
        response = new Message();
        response->setMessageType( KEY_EXCHANGE );
        response->setNonce( *nonce );
        response->set_DH_key( param->getMessage(), param->length() );
        delete param;

        this->userRegister.setLogged( username , this->cipherServer.getSessionKey( message->getDHkey() , message->getDHkeyLength()));

        if( !this->cipherServer.toSecureForm( response )){

            verbose << "--> [MainServer][keyExchangeHandler] Error, during message generation" << '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    //  the handler manages the USER_LIST_REQ requests. After it has verified the message consistency it generates
    //  a message containing a formatted list of all the match-available users connected to the server
    Message* MainServer::userListHandler( Message* message  , string username ) {

        int* nonce = message->getNonce();
        if( !nonce ){

            verbose<<"--> [MainServer][userListHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string( "MISSING_NONCE" ), nonce );

        }

        Message* response;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername() )){

            verbose<<"--> [MainServer][userListHandler] Error. Verification Failure"<<'\n';
            response = this->sendError( string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;

        }

        if( *(this->userRegister.getStatus( username )) != LOGGED ){

            verbose << "--> [MainServer][rankListHandler] Error, user not allowed" << '\n';
            response = this->sendError(string("INVALID_REQUEST"), nonce );

            delete nonce;
            return response;

        }

        vverbose << "--> [MainServer][userListHandler] Request has passed security checks" << '\n';

        NetMessage *user_list = this->userRegister.getUserList( username );
        response = new Message();

        response->setMessageType( USER_LIST );
        response->setNonce( *nonce );
        response->setUserList( user_list->getMessage(), user_list->length() );

        delete user_list;

        if( !this->cipherServer.toSecureForm(response ) ){

            verbose << "--> [MainServer][userListHandler] Error during message generation" << '\n';
            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }

    Message* MainServer::rankListHandler( Message* message  , string username ){

        int* nonce = message->getNonce();
        if( !nonce ){
            verbose<<"--> [MainServer][rankListHandler] Error, invalid message. Missing Nonce"<<'\n';
            return this->sendError( string( "MISSING_NONCE" ), nonce );
        }

        Message* response;

        if( !this->cipherServer.fromSecureForm( message, message->getUsername() )){

            verbose<<"--> [MainServer][rankListHandler] Error. Verification Failure"<<'\n';
            response = this->sendError( string( "VERIFICATION_ERROR" ), nonce );

            delete nonce;
            return response;

        }


        if( *(this->userRegister.getStatus(username)) != LOGGED ){

            verbose << "--> [MainServer][rankListHandler] Error, user not allowed" << '\n';
            response = this->sendError(string( "MISSING USERNAME" ), nonce );

            delete nonce;
            return response;

        }

        response = new Message();
        string rank_list = SQLConnector::getRankList();

        response->setMessageType( RANK_LIST );
        response->setNonce( *nonce );
        response->setRankList( (unsigned char*) rank_list.c_str(), rank_list.length() );

        if( !this->cipherServer.toSecureForm(response ) ){

            verbose << "-->[MainServer][rankListHandler] Error. Verification Failure"<< '\n';
            delete response;
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

        }

        delete nonce;
        return response;

    }



    Message* MainServer::logoutHandler( Message* message , string username ){

        int *nonce = message->getNonce();
        if (!nonce) {

            verbose << "--> [MainServer][logoutHandler] Error, invalid message. Missing Nonce" << '\n';
            return this->sendError(string( "MISSING_NONCE" ), nonce );

        }

        Message* response;

        if( !this->cipherServer.fromSecureForm( message , username ) ){

            verbose << "--> [MainServer][logoutHandler] Error, Verification failure" << '\n';
            response = this->sendError(string( "SECURITY_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        if( *(this->userRegister.getStatus(username)) != LOGGED ){

            verbose << "--> [MainServer][logoutHandler] Error, user not in the correct state" << '\n';
            response = this->sendError(string( "INVALID_REQUEST" ), nonce );

            delete nonce;
            return response;

        }

        response = new Message();
        response->setMessageType(LOGOUT_OK );
        response->setNonce( *nonce );

        /*
        matches = this->matchRegister.getAllMatchID(username);
        for( int i : matches ) {
    info = this->matchRegister.getMatch(i);
        //  prelevare socket
        //  invio messaggio ricevuto
        this->closeMatch(i);
        }*/

        if( !this->userRegister.removeUser(username)){

            verbose << "-->[MainServer][logoutHandler] Error. User not found"<< '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

            delete nonce;
            return response;
        }

        if( !this->cipherServer.toSecureForm( response )){

            verbose << "-->[MainServer][logoutHandler] Error. User not found"<< '\n';

            delete response;
            response = this->sendError(string( "SERVER_ERROR" ), nonce );

        }

        delete nonce;
        return response;

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

}

int main() {

    Logger::setThreshold( VERBOSE );
    MainServer* server = new MainServer( string("127.0.0.1") , 12345 );
    server->server();
    return 0;


}




