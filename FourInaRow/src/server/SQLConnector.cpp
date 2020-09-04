
#include "SQLConnector.h"

namespace server {

    ///////////////////////////////////////////////////////////////////////////////////////////////
    //                                                                                           //
    //                                      PUBLIC FUNCTIONS                                     //
    //                                                                                           //
    ///////////////////////////////////////////////////////////////////////////////////////////////

    //  the function contact a remote sql database to generate and return a formatted string containing of the users rank
    string SQLConnector::getRankList() {
        string ret = "RANK LIST\n";
        try {

            vverbose<<"--> [SQLConnector][getRankList] Starting to get user rank list"<<'\n';
            sql::Connection *con;
            sql::Statement *stmt;
            sql::ResultSet *res;
            sql::mysql::MySQL_Driver *driver;

            try {

                driver = sql::mysql::get_driver_instance();

            }catch(sql::SQLException &e){

                verbose<<"--> [SQLConnector][getRankList] Error, unable to locate the MySQL driver"<<'\n';
                return nullptr;

            }
            con = driver->connect("tcp://remotemysql.com:3306", "001RO3nHUn", "88lWUz0aB1");

            con->setSchema("001RO3nHUn");
            stmt = con->createStatement();
            res = stmt->executeQuery("SELECT * FROM `Rank`;");


            string value;
            vverbose<<"--> [SQLConnector][getRankList] Request completed, formatting the results"<<'\n';
            while (res->next()) {

                ret.append("\n\tusername: " );
                value = res->getString("username");
                ret.append(value );
                if( value.length() > 5 )
                    ret.append("\ttotalMatch: " );
                else
                    ret.append( "\t\ttotalMatch: ");
                ret.append( to_string(res->getInt("totalMatch") ));
                ret.append( "\t\twonMatch: ");
                ret.append( to_string( res->getInt("wonMatch") ));
                ret.append( "\t\tlooseMatch: ");
                ret.append( to_string( res->getInt("loseMatch")));
                ret.append( "\t\ttieMatch: ");
                ret.append( to_string( res->getInt("tieMatch")));

            }

            delete res;
            delete stmt;
            delete con;

            return ret;

        } catch (sql::SQLException &e ) {

            verbose<<"--> [SQLConnector][getRankList] Error, mySQL error: "<<e.getErrorCode()<<'\n';
            return ret;

        }

    }

    //  the function increment a user game statistic by increment the total game count and basing on the won value the wonMatch or loseMatch
    bool SQLConnector::incrementUserGame( string username, GameResult result ) {

        vverbose<<"--> [SQLConnector][incrementUserGame] Starting to update "<< username<<" statistic"<<'\n';

        if( !checkField ){

            verbose<<"--> [SQLConnector][incrementUserGame] Error, invalid username: "<<username<<'\n';
            return false;

        }

        try {

            sql::Connection *con;
            sql::Statement *stmt;
            sql::mysql::MySQL_Driver *driver;

            try {

                driver = sql::mysql::get_driver_instance();

            }catch(sql::SQLException &e){

                verbose<<"--> [SQLConnector][incrementUserGame] Error, unable to load MySQL driver"<<'\n';
                return false;

            }
            con = driver->connect("tcp://remotemysql.com:3306", "001RO3nHUn", "88lWUz0aB1");

            con->setSchema("001RO3nHUn");
            stmt = con->createStatement();
            string query = "UPDATE `Rank` SET totalMatch =totalMatch+1,";

            switch( result ){
                case WIN:
                    query.append( " wonMatch = wonMatch+1 WHERE username ='");
                    break;
                case LOOSE:
                    query.append( " loseMatch=loseMatch+1 WHERE username ='");
                    break;
                case TIE:
                    query.append( " tieMatch=tieMatch+1 WHERE username ='");
                    break;
                default:
                    return false;

            }

            query.append( username );
            query.append( "';" );
            stmt->execute(query );

            delete stmt;
            delete con;
            vverbose<<"--> [SQLConnector][incrementUserGame] Query correctly executed"<<'\n';

            return true;

        } catch (sql::SQLException &e) {

            verbose<<"--> [SQLConnector][incrementUserGame] Error, mySQL error: "<<e.getErrorCode()<<'\n';
            return false;
        }

    }

    //  the function is used to verify that the params of a query doesn't contain invalid character that could be used to generate an injection attack
    bool SQLConnector::checkField( string username ){
        vverbose<<"--> [SQLConnector][checkField] Starting verification of parameter: "<<username<<'\n';
        const char* value = username.c_str();
        for( int a = 0; a<username.length(); a++ ){
            if( (int)value[a] < 48 )
                return false;
            if( (int)value[a] > 57 && (int)value[a] < 65 )
                return false;
            if( (int)value[a] >90 && (int) value[a] < 97 )
                return false;
            if( (int)value[a] >122 )
                return false;
        }
        vverbose<<"--> [SQLConnector][checkField] Verification correctly performed"<<'\n';
        return true;
    }

}