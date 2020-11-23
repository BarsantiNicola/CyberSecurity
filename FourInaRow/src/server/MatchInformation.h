
#ifndef FOURINAROW_MATCHINFORMATION_H
#define FOURINAROW_MATCHINFORMATION_H

#include <iostream>
#include <vector>
#include "../Logger.h"
#define NUMBER_ROW 6
#define NUMBER_COLUMN 7

using namespace std;

namespace server {

    enum MatchStatus{

        OPENED,       //  match is allocated
        ACCEPTED,     //  match is accepted by the challenged
        READY,        //  challenger is advertised
        LOADED,       //  challenged received parameter
        STARTED,      //  challenger received parameter -> start user game protocol
        CLOSED        //  match closed by one of the users

    };

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                   MATCH INFORMATION                               //
    //    The class maintains information about a match and provides methods to          //
    //    modify and verify its status. The class maintains also the list of all the     //
    //    chosen columns during the match and permits to control the trend of the game   //
    //    and determine its conclusion and update the user ranking table                 //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class MatchInformation{

        private:
            string challenger;                          //  PLAYER WHICH HAS SENT THE INITIAL REQUEST
            string challenged;                          //  PLAYER WHICH HAS TO ACCEPT THE REQUEST
            int gameBoard[NUMBER_COLUMN][NUMBER_ROW];   //  GAMEBOARD TO REPLICATE THE MATCH TREND
            int nMoves;                                 //  TO EASILY IDENTIFY THE END OF A MATCH FOR A FULLY TABLE(TIE)
            bool control;                               //  VARIABLE TO KNOW THE PLAYER WHICH IS IN CHARGE OF MAKING THE NEXT MOVE
            MatchStatus status;                         //  STATUS OF A MATCH TO IDENTIFY THE CORRECT BEHAVIOR FOR CLOSE IT
            int controlAlignment( int row, int column, bool myMove );  //  FUNCTION TO IDENTIFY A POSSIBLE WINNER

        public:
            MatchInformation( string challenger, string challenged );

            string getChallenger();
            string getChallenged();
            MatchStatus getStatus();

            bool setStatus( MatchStatus status );

            int addChallengerMove( int chosen_col );        //  INSERT A NEW MOVE FOR THE CHALLENGER PLAYER
            int addChallengedMove( int chosen_col );        //  INSERT A NEW MOVE FOR THE CHALLENGED PLAYER
            int  verifyMatch();                             //  VERIFY THE RESULT OF A MATCH(1 WIN 0 TIE -1 NO_CONCLUSION)
            bool hasUser( string username );                //   VERIFY THE PRESENCE OF A USER INTO THE MATCH AS A CHALLENGER OR CHALLENGED
            bool isChallenger( string username );           //  VERIFY IF THE USER IS THE CHALLENGER FOR THE MATCH
            int getTotalMoves();                            //  GIVES THE TOTAL MOVES MADE INTO THE MATCH
            bool hasControl( string username );             //  VERIFY IF THE USER IS IN CHARGE FOR THE NEXT MOVE
            int verifyGame( int row, int column, string username );  //  VERIFY THE STATUS OF A MATCH(1 WIN 0 TIE -1 NO CONCLUSION)

    };

}

#endif //FOURINAROW_MATCHINFORMATION_H
