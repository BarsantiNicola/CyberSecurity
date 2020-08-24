
#include "MatchRegister.h"

namespace server{

    bool MatchRegister::addMatch( string challenger , string challenged ){

        if( this->matchRegister.size() == this->matchRegister.max_size()){

            verbose<<"--> [MatchRegister][addMatch] Error, the register is full"<<'\n';
            return false;

        }

        if( this->getMatchID(challenger) != nullptr ){

            verbose<<"--> [MatchRegister][addMatch] Error, the user is already setted for a match"<<'\n';
            return false;

        }

        while( this->hasMatchID( matchID )) this->matchID++;
        MatchInformation match( this->matchID , challenger , challenged );

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
        if( match->getStatus() != OPEN ){

            verbose<<"-->[MatchRegister][setAccepted] Error the match'status is invalid to perform ACCEPT: "<<match->getStatus()<<'\n';
            return false;

        }

        match->setStatus( ACCEPT );
        this->removeMatch( matchID );
        try{

            this->matchRegister.emplace_back(*match);

        }catch(const bad_alloc& e){

            verbose<<"-->[MatchRegister][setAccepted] Error bad allocation"<<'\n';
            return false;

        }

        delete match;
        return true;

    }

    bool MatchRegister::setLoaded( int matchID ){

        MatchInformation* match = this->getMatch( matchID );
        if( !match ){

            verbose<<"-->[MatchRegister][setLoaded] Error bad allocation"<<'\n';
            return false;

        }
        if( match->getStatus() != ACCEPT ){

            verbose<<"-->[MatchRegister][setLoaded] Error the match'status is invalid to perform LOAD: "<<match->getStatus()<<'\n';
            return false;

        }

        match->setStatus( LOAD );
        this->removeMatch( matchID );
        try{

            this->matchRegister.emplace_back(*match);

        }catch(const bad_alloc& e){

            verbose<<"-->[MatchRegister][setLoaded] Error bad allocation"<<'\n';
            return false;

        }

        delete match;
        return true;

    }

    bool MatchRegister::setStarted( int matchID ) {

        MatchInformation *match = this->getMatch(matchID);
        if (!match) {

            verbose << "-->[MatchRegister][setStarted] Error bad allocation" << '\n';
            return false;

        }
        if (match->getStatus() != LOAD) {

            verbose << "-->[MatchRegister][setStarted] Error the match'status is invalid to perform START: "
                    << match->getStatus() << '\n';
            return false;

        }

        match->setStatus(START);
        this->removeMatch(matchID);
        try {

            this->matchRegister.emplace_back(*match);

        } catch (const bad_alloc &e) {

            verbose << "-->[MatchRegister][setStarted] Error bad allocation" << '\n';
            return false;

        }

        delete match;
        return true;

    }

    bool MatchRegister::setRejected( int matchID ) {

        MatchInformation *match = this->getMatch(matchID);
        if (!match) {

            verbose << "-->[MatchRegister][setStarted] Error bad allocation" << '\n';
            return false;

        }

        match->setStatus(REJECT);
        this->removeMatch(matchID);
        try {

            this->matchRegister.emplace_back(*match);

        } catch (const bad_alloc &e) {

            verbose << "-->[MatchRegister][setLoaded] Error bad allocation" << '\n';
            return false;

        }

        delete match;
        return true;
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
            if( this->matchRegister.at(a).getMatchID() == matchID )
                return new MatchInformation( matchID, this->matchRegister.at(a).getChallenger() , this->matchRegister.at(a).getChallenged());
        return nullptr;

    }

}