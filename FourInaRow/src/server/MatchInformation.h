
#ifndef FOURINAROW_MATCHINFORMATION_H
#define FOURINAROW_MATCHINFORMATION_H

#include <iostream>

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
            string challenged;
            MatchStatus status;

        public:
            MatchInformation( int matchID , string challenger, string challenged );
            int getMatchID();
            string getChallenger();
            string getChallenged();
            MatchStatus getStatus();
            void setStatus( MatchStatus status );

    };
}

#endif //FOURINAROW_MATCHINFORMATION_H
