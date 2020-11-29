
#ifndef TEXTUAL_INTERFACE_MANAGER
#define TEXTUAL_INTERFACE_MANAGER
#include <iostream>
#include <fstream>
#include <vector>
#include <unistd.h>
#include <sys/wait.h>
#include <unordered_map>
#include "../Logger.h"

#define USERNAME_POSITION 1712
#define SERVERSTATUS_POSITION 1842
#define PENDING_LIST_SIZE_POSITION 1789
#define MATCH_STATUS_POSITION 1905
#define ACTIVE_USERS_POSITION 1962
#define TIME_POSITION 1299
#define START_CHAT_POSITION 1451
#define START_GAMEBOARD_POSITION 1660
#define LOCAL_GAMEBOARD_POSITION 90
#define NUMBER_COLLUMN_FOR_ROW 121
#define ROW_OF_GAMEBOARD_START 10

using namespace std;

namespace client{
	

	enum class InterfacePage{

	    MAIN_PAGE_0,
        LOGIN_PAGE_0,
        MATCH_PAGE_0

	};

    enum Command{

        CLEAR,    //  CLEAR THE TERMINAL
        RAW,      //  SET INPUT TYPE AS RAW     [USED INTO SETTER]
        COOKED    //  SET INPUT TYPE AS COOKED  [USED INTO SETTER]

    };

	enum class InputType{

		USERNAME,
		SERVER_STATUS,
		ACTIVE_USER,
		PENDING_SIZE,
		MATCH_STATUS,
        TIMER,
        CHAT,
        GAMEBOARD

	};

	struct Statistic{

	    int won;
	    int lose;
	    int tie;

	};

    ///////////////////////////////////////////////////////////////////////////////////////
    //                                                                                   //
    //                                TEXTUALINTERFACEMANAGER                            //
    //                                                                                   //
    //    The class is in charge of generating the user interface of the application     //
    //    In particular to format the information to be printed and insert them into a   //
    //    colored textual interface. The class maintains methods to completely manage    //
    //    every aspects of the output from printing the interface to update and insert   //
    //    information into it                                                            //
    //                                                                                   //
    ///////////////////////////////////////////////////////////////////////////////////////

	class TextualInterfaceManager{
	
	    private:
		    string login_page;      //  FORMATTED LOGIN_PAGE
		    string main_page;       //  FORMATTED MAIN_PAGE
		    string game_page;       //  FORMATTED GAME_PAGE
		    string setter_page;     //  FORMATTED SETTER_PAGE
            string username;        //  USERNAME USED INTO THE CLIENT
            char chatLines[10][50]; //  FORMATTED LINES FOR CHAT
		    int** gameBoard;        //  SHARED GAMEBOARD DATA
		    bool last;

		    int adj_x;              //  X VALUE OF ADJUSTMENT OF PAGE
            int adj_y;              //  Y VALUE OF ADJUSTMENT OF PAGE

	    public:
		    TextualInterfaceManager();
		    string* getUsername();
		    void printUserList( char* userList, int len );
		    void printRankList( char* rankList, int len, bool print=true );
		    void printUserPending( vector<string> username );
		    void printLoginInterface();
		    void printMessage( string message );
		    void printMainInterface(string username,string activeUser,string serverStatus,string matchStatus,string pendingStatus);
		    void printGameInterface(bool myMove, string timer,string chat,string gameBoard);
            void printSetterPage();
		    bool setGame(int** game);
            int getXTranslation();
            int getYTranslation();
		    void setUsername(string username);
		    void printRankOrUserList(string message);
		    void printLine(int line);
		    bool setChat( string username, char message[], int len );
		    void resetChat();
		    void printGameline( int line );
		    void resetGameboard();
		    static void showTimer( int time,int x, int y );
		    static void resetTimer(int x, int y );
		    bool setter();


	private:
		string insertElement( InterfacePage page , InputType input , string value , string base);
        void execCommand( Command command );
	};

}

#endif
