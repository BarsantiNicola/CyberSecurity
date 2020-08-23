
#ifndef FOURINAROW_SQLCONNECTOR_H
#define FOURINAROW_SQLCONNECTOR_H

#include "../Logger.h"
#include <mysql_connection.h>
#include <mysql_driver.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <cstring>
#include <stdlib.h>
#include <stdio.h>
using namespace std;

namespace server {

    /////////////////////////////////////////////////////////////////////////////////////
    //                                                                                 //
    //                                 SQLCONNECTOR                                    //
    //    The class gives a set of functions to get the user rank list and update      //
    //    users statistics from a remote MySQL database localized on remotemysql.com   //
    //    To prevent injections attack the update query verify that the given username //
    //    doesn't contains an invalid character by use a white list verification.      //
    //                                                                                 //
    /////////////////////////////////////////////////////////////////////////////////////

    class SQLConnector {
        private:
            static bool checkField( string username );                  //  WHITELIST VERIFICATION

        public:
            static string getRankList();                                //  GIVES A FORMATTED STRING OF THE USERS RANKS
            static bool incrementUserGame(string username, bool won);   //  UPDATE THE USER STATISTICS WITH A WON/LOSE MATCH

    };

}
#endif //FOURINAROW_SQLCONNECTOR_H
