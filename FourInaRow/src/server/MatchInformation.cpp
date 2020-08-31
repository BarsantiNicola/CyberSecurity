
#include "MatchInformation.h"

namespace server{

    MatchInformation::MatchInformation( string challenger, string challenged ){

        this->challenger = challenger;
        this->challenged = challenged;
        this->status = OPENED;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           GETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    string MatchInformation::getChallenger(){

        return this->challenger;

    }
    string MatchInformation::getChallenged(){

        return this->challenged;

    }

    MatchStatus MatchInformation::getStatus(){

        return this->status;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                           SETTERS                                         //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    // sets the status of a match verifing that the correct logic is respected
    //   OPENED->ACCEPTED->READY->LOADED->STARTED   [CLOSED AVAILABLE ALWAYS]
    bool MatchInformation::setStatus( MatchStatus status ){

        if( status == ACCEPTED && this->status != OPENED ) return false;
        if( status == READY && this->status != ACCEPTED ) return false;
        if( status == LOADED && this->status != READY ) return false;
        if( status == STARTED && this->status != LOADED ) return false;

        this->status = status;
        return true;

    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                     PUBLIC FUNCTIONS                                      //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  used to register users moves during the challenge
    bool MatchInformation::addChallengerMove( int chosen_col ){

        if( this->status != STARTED ) return false;

        try {

            this->challengerMoves.emplace_back( chosen_col );
            return true;

        }catch(const bad_alloc& e){

            verbose<<"--> [MatchInformation][addChallengerMove] Error, during memory allocation"<<'\n';
            return false;

        }

    }

    //  used to register users moves during the challenge
    bool MatchInformation::addChallengedMove( int chosen_col ){


        if( this->status != STARTED ) return false;

        try {

            this->challengedMoves.emplace_back( chosen_col );
            return true;

        }catch(const bad_alloc& e){

            verbose<<"--> [MatchInformation][addChallengedMove] Error, during memory allocation"<<'\n';
            return false;

        }

    }

    //  the function calculates the result of the match to verify the winner
    int  MatchInformation::verifyMatch(){
        return 0;
    }

    //  the function controls if a user is present as a challenger or challenged
    bool MatchInformation::hasUser( string username ){

        return (this->challenger.compare(username) == 0) || (this->challenged.compare(username) == 0);
    }

    //  the function controls if a user is set as challenger
    bool MatchInformation::isChallenger( string username ){

        return this->challenger.compare(username) == 0;
    }

}