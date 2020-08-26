
#ifndef FOURINAROW_MATCHREGISTER_H
#define FOURINAROW_MATCHREGISTER_H

#include "MatchInformation.h"
#include "../Logger.h"
#include <vector>

namespace server {

    class MatchRegister{

    private:
        vector<MatchInformation> matchRegister;
        int matchID = 0;

    public:
        bool addMatch( string challenger , string challenged , int nonce );
        bool setAccepted( int matchID );
        bool setLoaded( int matchID );
        bool setStarted( int matchID );
        bool setRejected( int matchID );
        bool removeMatch( int matchID );
        int* getMatchID( string challenger );
        bool hasMatchID( int match );
        MatchInformation* getMatch( int matchID );
        vector<int> getAllMatchID(string username);
        int* getNonce( int matchID );
        static void test();

    };

}


#endif //FOURINAROW_MATCHREGISTER_H
