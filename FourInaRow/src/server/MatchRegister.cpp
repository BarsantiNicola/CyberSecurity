
#include "MatchRegister.h"

namespace server{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PUBLIC FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  insert a new match into the register
    bool MatchRegister::addMatch( string challenger , string challenged ){

        if( this->matchRegister.size() == this->matchRegister.max_size()){

            verbose<<"--> [MatchRegister][addMatch] Error, the register is full"<<'\n';
            return false;

        }

        MatchInformation match( challenger , challenged );

        try{

            this->matchRegister.emplace_back( match );
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][addMatch] Error during memory allocation, operation aborted"<<'\n';
            return false;

        }

    }

    //  remove a match identified from its ID from the register
    bool MatchRegister::removeMatch( int matchID ){

        try{

            this->matchRegister.erase( this->matchRegister.begin() + matchID );
            return true;

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  set the status of a match identified by its ID as ACCEPTED
    bool MatchRegister::setAccepted( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( ACCEPTED );

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][setAccepted] Error during memory allocation, operation aborted"<<'\n';
            return false;
        }

    }

    //  set the status of a match identified by its ID as READY
    bool MatchRegister::setReady( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( READY );

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][setReady] Error during memory allocation, operation aborted"<<'\n';
            return false;
        }

    }

    //  set the status of a match identified by its ID as LOAD
    bool MatchRegister::setLoaded( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( LOADED );

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][setLoaded] Error during memory allocation, operation aborted"<<'\n';
            return false;
        }

    }

    //  set the status of a match identified by its ID as STARTED
    bool MatchRegister::setStarted( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( STARTED );

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][setStarted] Error during memory allocation, operation aborted"<<'\n';
            return false;
        }

    }

    //  set the status of a match identified by its ID as CLOSE
    bool MatchRegister::setClosed( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( CLOSED );

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][setClosed] Error during memory allocation, operation aborted"<<'\n';
            return false;
        }

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  search a match basing on its challenger and return its ID. -1 in case of match not found
    int MatchRegister::getMatchID( string challenger ) {

        for( int a = 0; a< this->matchRegister.size(); a++ )
            if( !this->matchRegister[a].getChallenger().compare(challenger))
                return a;

        vverbose<<"--> [MatchRegister][getMatchID] Match not found"<<'\n';
        return -1;

    }

    //  returns a list of IDs for the matches where the given username appears both as a challenged or challenger
    vector<int> MatchRegister::getMatchIds( string username ) {

        vector<int> ret;

        for( int a = 0; a< this->matchRegister.size(); a++ )
            if( !this->matchRegister[a].getChallenger().compare(username) || !this->matchRegister[a].getChallenged().compare(username))
                try{

                    ret.emplace_back(a);

                }catch( bad_alloc e ){

                    verbose<<"--> [MatchRegister][getMatchIds] Error during memory allocation, operation aborted"<<'\n';
                    break;

                }

        return ret;

    }

    //  return the ID of a started match where the given username appears
    int MatchRegister::getMatchPlay( string username ){

        for( int a = 0; a<this->matchRegister.size(); a++ )
            if( this->matchRegister[a].getStatus() == STARTED )
                if( !this->matchRegister[a].getChallenger().compare(username) || !this->matchRegister[a].getChallenged().compare(username))
                    return a;

        vverbose<<"--> [MatchRegister][getMatchPlay] Match not found"<<'\n';
        return -1;

    }

    //  return the status of a match identified by its matchID
    MatchStatus* MatchRegister::getMatchStatus( int matchID ){

        try{

            return new MatchStatus(this->matchRegister[matchID].getStatus());

        }catch( bad_alloc e ){

            verbose<<"--> [MatchRegister][getMatchStatus] Error during memory allocation, operation aborted"<<'\n';
            return nullptr;
        }

    }

    //  return the challenged username from the match identified by its matchID
    string MatchRegister::getChallenged( int matchID ){

        return this->matchRegister[matchID].getChallenged();

    }

    //  return the challenger username from the match identified by its matchID
    string MatchRegister::getChallenger( int matchID ){

        return this->matchRegister[matchID].getChallenger();

    }

    //  return the challenger username from the match identified by its matchID
    int MatchRegister::getTotalMoves( int matchID ){

        return this->matchRegister[matchID].getTotalMoves();

    }

    //  insert a move into the match identified by its matchID
    int MatchRegister::addChallengerMove( int matchID, int chosen_col ){

        if( matchID != -1 )
            return this->matchRegister[matchID].addChallengerMove(chosen_col);

        verbose<<"--> [MatchRegister][addChallengerMove] Error, match not found"<<'\n';
        return -2;

    }

    //  return the challenged username from the match identified by its matchID
    int MatchRegister::addChallengedMove( int matchID, int chosen_col ){

        if( matchID != -1 )
            return this->matchRegister[matchID].addChallengedMove(chosen_col);

        verbose<<"--> [MatchRegister][addChallengedMove] Error, match not found"<<'\n';
        return -2;

    }

}