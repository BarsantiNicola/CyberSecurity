
#ifndef FOURINAROW_MATCHINFORMATION_H
#define FOURINAROW_MATCHINFORMATION_H

#include <iostream>
#include <vector>
using namespace std;

namespace server {

    enum MatchStatus{

        OPEN,
        ACCEPT,
        LOAD,
        START,
        REJECT

    };

    class MatchInformation{

        private:
            int matchID;
            string challenger;
            vector<int> challengerMoves;
            string challenged;
            vector<int> challengedMoves;
            MatchStatus status;
            int nonce;

        public:
            MatchInformation( int matchID , string challenger, string challenged, int nonce );
            int getMatchID();
            int getNonce();
            string getChallenger();
            string getChallenged();
            MatchStatus getStatus();
            void setStatus( MatchStatus status );

    };
}

#endif //FOURINAROW_MATCHINFORMATION_H
