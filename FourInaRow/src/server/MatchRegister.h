
#ifndef FOURINAROW_MATCHREGISTER_H
#define FOURINAROW_MATCHREGISTER_H

#include "MatchInformation.h"
#include "../Logger.h"
#include <vector>

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                     MATCH REGISTER                                //
    //    The class maintains information about a started matches and provides methods   //
    //    to add matches, set their status and rapidly collect information and search    //
    //    users into the register.
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class MatchRegister{

        private:
            vector<MatchInformation> matchRegister;

        public:
            bool addMatch( string challenger , string challenged );
            bool removeMatch( int matchID );

            bool setAccepted( int matchID );
            bool setReady( int matchID );
            bool setLoaded( int matchID );
            bool setStarted( int matchID );
            bool setClosed( int matchID );

            int getMatchID( string challenger );              //  GET THE MATCH ID OF A MATCH OF A USER, -1 IF NO MATCH FOUND
            vector<int> getMatchIds( string username );       //  RETURN A LIST OF MATCH IDS OF MATCH WHERE THE USER IS PRESENT

            MatchStatus* getMatchStatus( int matchID );       //  RETURN THE STATUS OF A MATCH. NULL IF THE MATCH DOESN'T EXIST
            int* verifyMatch( int matchID );                  //  RETURN THE STATUS OF THE MATCH BY THE CHALLENGER POINT OF VIEW(1 WIN, -1 LOSE, 0 TIE)
            string getChallenged( int matchID );
    };

}


#endif //FOURINAROW_MATCHREGISTER_H
