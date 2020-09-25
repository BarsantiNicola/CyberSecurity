
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
    //    chosen columns during the match and permits to verify the winner.              //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

    class MatchInformation{

        private:
            string challenger;
            string challenged;
            int gameBoard[NUMBER_COLUMN][NUMBER_ROW];
            int nMoves;
            unsigned int token;
            bool control;
            MatchStatus status;
            int controlAlignment( int row, int column, bool myMove );
        public:
            MatchInformation( string challenger, string challenged );

            string getChallenger();
            string getChallenged();
            MatchStatus getStatus();

            bool setStatus( MatchStatus status );

            int addChallengerMove( int chosen_col );
            int addChallengedMove( int chosen_col );
            int  verifyMatch();                             //  verify the result of the match(-1 win challenger 1 win challenged 0 tie)
            bool hasUser( string username );               //  verify the presence of a user(-1 challenger 1 challenged 0 no presence)
            bool isChallenger( string username );
            int getTotalMoves();
            bool hasControl( string username );
            int verifyGame( int row, int column, string username );
            bool verifyToken( int token );
    };
}

#endif //FOURINAROW_MATCHINFORMATION_H
