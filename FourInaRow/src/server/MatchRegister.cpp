
#include "MatchRegister.h"

namespace server{

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PUBLIC FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    bool MatchRegister::addMatch( string challenger , string challenged ){

        if( this->matchRegister.size() == this->matchRegister.max_size()){

            verbose<<"--> [MatchRegister][addMatch] Error, the register is full"<<'\n';
            return false;

        }

        MatchInformation match( challenger , challenged );

        try{

            this->matchRegister.emplace_back( match );
            return true;

        }catch(const bad_alloc& e){

            verbose<<"-->[MatchRegister][addMatch] Error during memory allocation"<<'\n';
            return false;

        }

    }

    bool MatchRegister::removeMatch( int matchID ){

        try{

            this->matchRegister.erase( this->matchRegister.begin() + matchID );
            return true;

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }


    int* MatchRegister::verifyMatch( int matchID ){

        try{

            return new int(this->matchRegister[matchID].verifyMatch());

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return nullptr;
        }

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    bool MatchRegister::setAccepted( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( ACCEPTED );

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    bool MatchRegister::setReady( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( READY );

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    bool MatchRegister::setLoaded( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( LOADED );

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    bool MatchRegister::setStarted( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( STARTED );

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    bool MatchRegister::setClosed( int matchID ){

        try{

            return this->matchRegister[matchID].setStatus( CLOSED );

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return false;
        }

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    int MatchRegister::getMatchID( string challenger ) {

        for( int a = 0; a< this->matchRegister.size(); a++ )
            if( !this->matchRegister[a].getChallenger().compare(challenger))
                return a;

        return -1;

    }
    vector<int> MatchRegister::getMatchIds( string username ) {

        vector<int> ret;

        for( int a = 0; a< this->matchRegister.size(); a++ )
            if( !this->matchRegister[a].getChallenger().compare(username) || !this->matchRegister[a].getChallenged().compare(username))
                try{
                    ret.emplace_back(a);
                }catch(exception e ){
                    break;
                }

        return ret;

    }

    MatchStatus* MatchRegister::getMatchStatus( int matchID ){

        try{

            return new MatchStatus(this->matchRegister[matchID].getStatus());

        }catch( exception e ){

            verbose<<"--> [MatchRegister][removeMatch] Error, location empty"<<'\n';
            return nullptr;
        }

    }
    string MatchRegister::getChallenged( int matchID ){

        return this->matchRegister[matchID].getChallenged();

    }

}