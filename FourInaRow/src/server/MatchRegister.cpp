
#include "MatchRegister.h"

namespace server{

    bool MatchRegister::addMatch( string challenger , string challenged , int nonce ){

        if( this->matchRegister.size() == this->matchRegister.max_size()){

            verbose<<"--> [MatchRegister][addMatch] Error, the register is full"<<'\n';
            return false;

        }

        if( this->getMatchID(challenger) != nullptr ){

            verbose<<"--> [MatchRegister][addMatch] Error, the user is already setted for a match"<<'\n';
            return false;

        }

        while( this->hasMatchID( matchID )) this->matchID++;
        MatchInformation match( this->matchID , challenger , challenged , nonce );

        try{

            this->matchRegister.emplace_back(match);

        }catch(const bad_alloc& e){

            verbose<<"-->[MatchRegister][addMatch] Error bad allocation"<<'\n';
            return false;

        }
        return true;

    }

    bool MatchRegister::setAccepted( int matchID ){

        MatchInformation* match = this->getMatch( matchID );
        if( !match ){

            verbose<<"-->[MatchRegister][setAccepted] Error bad allocation"<<'\n';
            return false;

        }
        if( match->getStatus() != LOADED ){

            verbose<<"-->[MatchRegister][setAccepted] Error the match'status is invalid to perform ACCEPT: "<<match->getStatus()<<'\n';
            return false;

        }
        delete match;

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if (this->matchRegister.at(a).getMatchID() == matchID) {
                this->matchRegister[a].setStatus(ACCEPTED );
                return true;
            }
        return false;

    }

    bool MatchRegister::setLoaded( int matchID ){

        MatchInformation* match = this->getMatch( matchID );

        if( !match ){

            verbose<<"-->[MatchRegister][setLoaded] Error bad allocation"<<'\n';
            return false;

        }
        if( match->getStatus() != OPENED ){

            verbose<<"-->[MatchRegister][setLoaded] Error the match'status is invalid to perform LOAD: "<<match->getStatus()<<'\n';
            return false;

        }
        delete match;

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if (this->matchRegister.at(a).getMatchID() == matchID) {
                this->matchRegister[a].setStatus(LOADED );
                return true;
            }
        return false;

    }

    bool MatchRegister::setStarted( int matchID ) {


        MatchInformation *match = this->getMatch(matchID);
        if (!match) {

            verbose << "-->[MatchRegister][setStarted] Error bad allocation" << '\n';
            return false;

        }
        if (match->getStatus() != ACCEPTED ) {

            verbose << "-->[MatchRegister][setStarted] Error the match'status is invalid to perform START: "
                    << match->getStatus() << '\n';
            return false;

        }

        delete match;

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if (this->matchRegister.at(a).getMatchID() == matchID) {
                this->matchRegister[a].setStatus(STARTED );
                return true;
            }
        return false;

    }

    bool MatchRegister::setRejected( int matchID ) {

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if (this->matchRegister.at(a).getMatchID() == matchID) {
                this->matchRegister[a].setStatus(CLOSED);
                return true;
            }
        return false;

    }

    bool MatchRegister::removeMatch( int matchID ){


        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( this->matchRegister.at(a).getMatchID() == matchID ) {
                this->matchRegister.erase(this->matchRegister.begin()+a);
                return true;
            }

        return false;

    }

    bool MatchRegister::hasMatchID(int match) {
        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( this->matchRegister.at(a).getMatchID() == matchID ) return true;
        return false;
    }

    int*  MatchRegister::getMatchID( string challenger ){

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( !this->matchRegister.at(a).getChallenger().compare(challenger) )
                return new int(a);
        return nullptr;

    }

    MatchInformation* MatchRegister::getMatch( int matchID ){

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( this->matchRegister.at(a).getMatchID() == matchID ) {
                MatchInformation *match = new MatchInformation(matchID, this->matchRegister.at(a).getChallenger(),
                                                               this->matchRegister.at(a).getChallenged(), this->matchRegister.at(a).getNonce());
                match->setStatus(this->matchRegister.at(a).getStatus());
                return match;
            }
        return nullptr;

    }

    vector<int> MatchRegister::getAllMatchID(string username){
        vector<int> ret;
        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( !this->matchRegister.at(a).getChallenger().compare(username) || !this->matchRegister.at(a).getChallenged().compare(username) ) {
                ret.emplace_back(a);
            }
        return ret;

    }

    int* MatchRegister::getNonce( int matchID ){
        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( this->matchRegister.at(a).getMatchID() == matchID ) {
                return new int( this->matchRegister[a].getNonce());
            }
        return nullptr;
    }

    void MatchRegister::test(){

        MatchRegister* reg = new MatchRegister();
        if( !reg->addMatch("marco" , "luca" , 2)) {
            base << "Error1" << '\n';
            return;
        }

        if( reg->addMatch("marco" , "lucia", 3)) {
            base << "Error2" << '\n';
            return;
        }

        if( !reg->addMatch("nicola" , "marco", 4)) {
            base << "Error3" << '\n';
            return;
        }
        MatchInformation* info;
        int* match = reg->getMatchID("luca");
        if( match ){
            base<<"Error4"<<'\n';
            return;
        }
        match = reg->getMatchID("marco");
        if( !match ){
            base<<"Error5"<<'\n';
            return;
        }
        info = reg->getMatch(*match);

        if( info->getChallenged().compare("luca")!= 0 ){
            base<<"Error6"<<'\n';
            return;
        }

        if( !reg->getMatchID("nicola")){

            base<<"Error7"<<'\n';
            return;
        }

        int* match2 = reg->getMatchID("nicola");



        if( !reg->setLoaded(*match)){
            base<<"Error8"<<'\n';
            return;
        }
        if( reg->setLoaded(5)){
            base<<"Error9"<<'\n';
            return;
        }
        match = reg->getMatchID("marco");
        if( !match ){
            base<<"Error10"<<'\n';
            return;
        }
        if( !reg->setAccepted(*match)){
            base<<"Error11"<<'\n';
            return;
        }
        if( reg->setAccepted(*match2)){
            base<<"Error12"<<'\n';
            return;
        }
        match = reg->getMatchID("marco");
        if( !match ){
            base<<"Error13"<<'\n';
            return;
        }
        if( !reg->setStarted(*match)){
            base<<"Error14"<<'\n';
            return;
        }
        if( reg->setStarted(*match2)){
            base<<"Error15"<<'\n';
            return;
        }
        match = reg->getMatchID("marco");
        if( !match ){
            base<<"Error16"<<'\n';
            return;
        }
        if( !reg->setRejected(*match)){
            base<<"Error17"<<'\n';
            return;
        }
        if( !reg->setRejected(*match2)){
            base<<"Error18"<<'\n';
            return;
        }
        match = reg->getMatchID("marco");
        if( !match ){
            base<<"Error19"<<'\n';
            return;
        }
        if( !reg->removeMatch(*match)){
            base<<"Error20"<<'\n';
            return;
        }
        if( reg->removeMatch(5)){
            base<<"Error21"<<'\n';
            return;
        }

        verbose<<"Success"<<'\n';
    }

}