
#include "MatchInformation.h"

namespace server{

    MatchInformation::MatchInformation( string challenger, string challenged ){

        this->challenger = challenger;
        this->challenged = challenged;
        this->status = OPEN;

    }
    string MatchInformation::getChallenger(){
        return this->challenger;
    }

    string MatchInformation::getChallenged(){
        return this->challenged;
    }

    MatchStatus MatchInformation::getStatus(){
        return this->status;
    }

    void MatchInformation::setStatus( MatchStatus status ){
        this->status = status;
    }

}