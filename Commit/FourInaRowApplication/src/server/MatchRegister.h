
#ifndef FOURINAROW_MATCHREGISTER_H
#define FOURINAROW_MATCHREGISTER_H

#include "MatchInformation.h"
#include "../Logger.h"
#include <vector>

namespace server {

    /////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                     //
    //                                     MATCH REGISTER                                  //
    //    The class maintains information about all started matches and provides methods   //
    //    to add matches, set their status and rapidly collect information and search      //
    //    users into the register. It permits also to insert a move into a match and       //
    //    gives feedbacks on its status(if a match is ended and if the case with a win or  //
    //    a tie)                                                                           //
    //                                                                                     //
    /////////////////////////////////////////////////////////////////////////////////////////

    class MatchRegister{

        private:
            vector<MatchInformation> matchRegister;

        public:
            bool addMatch( string challenger , string challenged );   //  ADDS A NEW MATCH TO THE REGISTER
            bool removeMatch( int matchID );                          //  REMOVES A MATCH TO THE REGISTER

            bool setAccepted( int matchID );                 //  CHANGES THE STATUS OF THE MATCH IDENTIFIED BY ITS ID TO ACCEPTED
            bool setReady( int matchID );                    //  CHANGES THE STATUS OF THE MATCH IDENTIFIED BY ITS ID TO READY
            bool setLoaded( int matchID );                   //  CHANGES THE STATUS OF THE MATCH IDENTIFIED BY ITS ID TO LOAD
            bool setStarted( int matchID );                  //  CHANGES THE STATUS OF THE MATCH IDENTIFIED BY ITS ID TO STARTED
            bool setClosed( int matchID );                   //  CHANGES THE STATUS OF THE MATCH IDENTIFIED BY ITS ID TO CLOSED

            int getMatchID( string challenger );              //  GETS THE MATCH ID OF A MATCH OF A USER, -1 IF NO MATCH FOUND
            int getMatchPlay( string username );              //  RETURNS THE ID OF A STARTED MATCH WHERE THE USER IS LINKED[-1 IN CASE NO MATCH FOUND]
            vector<int> getMatchIds( string username );       //  RETURNS A LIST OF MATCH IDS OF MATCH WHERE THE USER IS PRESENT

            MatchStatus* getMatchStatus( int matchID );       //  RETURNS THE STATUS OF A MATCH. NULL IF THE MATCH DOESN'T EXIST
            string getChallenged( int matchID );              //  RETURNS THE USERNAME OF THE CHALLENGED OF THE GIVEN MATCH IDENTIFIED BY ITS ID
            string getChallenger( int matchID );              //  RETURNS THE USERNAME OF THE CHALLENGER OF THE GIVEN MATCH IDENTIFIED BY ITS ID
            int getTotalMoves( int matchID );                 //  RETURNS THE NUMBER OF MADE MOVES INTO THE GIVEN MATCH IDENTIFIED BY ITS ID
            int addChallengerMove( int matchID, int chosen_col );  //  ADDS A MOVE FOR THE CHALLENGER IN THE GIVEN MATCH IDENTIFIED BY ITS ID AND RETURN A RESPONSE
            int addChallengedMove( int matchID, int chosen_col );  //  ADDS A MOVE FOR THE CHALLENGED IN THE GIVEN MATCH IDENTIFIED BY ITS ID AND RETURN A RESPONSE
    };

}


#endif //FOURINAROW_MATCHREGISTER_H
