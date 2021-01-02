
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
		    string win_page;        //  FORMATTED WIN_PAGE
		    string lose_page;       //  FORMATTED LOSE_PAGE
		    string tie_page;        //  FORMATTED TIE_PAGE
            string username;        //  USERNAME USED INTO THE CLIENT
            char chatLines[10][50]; //  FORMATTED LINES FOR CHAT
		    int** gameBoard;        //  SHARED GAMEBOARD DATA
		    bool last;

		    int adj_x;              //  X VALUE OF ADJUSTMENT OF PAGE
            int adj_y;              //  Y VALUE OF ADJUSTMENT OF PAGE

	    public:
		    TextualInterfaceManager();
		    string* getUsername();                          //  GIVES THE USERNAME SETTED INTO THE MAIN PAGE
		    void printUserList( char* userList, int len );                    //  PRINTS THE USER LIST
		    void printRankList( char* rankList, int len, bool print=true );   //  PRINTS THE RANK LIST
		    void printUserPending( vector<string> username );    //  PRINTS THE USER LIST
		    void printLoginInterface();                      //  SHOWS THE LOGIN PAGE
		    void printMessage( string message );             //  PRINTS MESSAGES(ERRORS, ADVICE) INTO THE INTERFACE
		    void printMainInterface(string username,string activeUser,string serverStatus,string matchStatus,string pendingStatus);  //  SHOWS THE MAIN PAGE
		    void printGameInterface(bool myMove, string timer,string chat,string gameBoard);   //  SHOWS THE GAME PAGE
            void printSetterPage();                          //  SHOWS THE SETTER PAGE
            void printWinGame();                             //  SHOWS MESSAGE WIN
            void printLoseGame();                            //  SHOWS MESSAGE LOSE
            void printTieGame();                             //  SHOWS MESSAGE TIE
		    bool setGame(int** game);                        //  SETS THE GAMEBOARD
            int getXTranslation();                           //  GIVES THE Y PARAMETER USED TO ADJUST THE PAGES
            int getYTranslation();                           //  GIVES THE X PARAMETER USED TO ADJUST THE PAGES
		    void setUsername(string username);               //  SETS THE USERNAME USED INTO THE MAIN_PAGE
		    void printLine(int line);                        //  PRINTS A LINE OF THE GAMEBOARD(USED INTO PRINT GAME_PAGE)
		    bool setChat( string username, char message[], int len );   //  SETS A CHAT MESSAGE INTO THE GAME_PAGE CONTAINER
		    void resetChat();                                //  RESETS THE CHAT CONTAINER INTO THE GAME_PAGE
		    void printGameline( int line );                  //  PRINTS A GAMEBOARD LINE(USED INTO PRINT GAMEPAGE)
		    void resetGameboard();                           //  RESETS THE GAMEBOARD
		    static void showTimer( int time,int x, int y );  //  SETS DINAMICALLY(WITHOUT REFRESH) THE TIMER INTO THE GAME_PAGE
		    static void resetTimer(int x, int y );  //  RESETS THE TIMER DINAMICALLY(WITHOUT REFRESH) INTO THE GAME_PAGE
		    bool setter();                        //  PAGE TO SET THE X,Y ADJUST PARAMETERS
            static string extractCommand( string input );     // EXTRACTS A COMMAND FROM A STRING

	private:
		string insertElement( InterfacePage page , InputType input , string value , string base);   //  INSERTS AN ELEMENT INTO THE PAGE
        void execCommand( Command command );       // EXECUTES A COMMAND INTO THE TERMINAL IN SECURE MODE

	};

}

#endif
