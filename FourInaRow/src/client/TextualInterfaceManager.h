
#ifndef TEXTUAL_INTERFACE_MANAGER
#define TEXTUAL_INTERFACE_MANAGER
#include <iostream>
#include <fstream>
#define USERNAME_POSITION 1712
#define SERVERSTATUS_POSITION 1842
#define PENDING_LIST_SIZE_POSITION 1789
#define MATCH_STATUS_POSITION 1905
#define ACTIVE_USERS_POSITION 1962
#define TIME_POSITION 940
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

	class TextualInterfaceManager{
	
	private:
		string login_page;
		string main_page;
		string game_page;
                string username;
                int adj_x;
                int adj_y;
		void* game;
	
	public:
		TextualInterfaceManager();
                string* getUsername();
		void printLoginInterface();
		void printColoredLogin();
		void printMainInterface(string username,string activeUser,string serverStatus,string matchStatus,string pendingStatus);
        void printColoredMain( string page );
		void printGameInterface(bool myMove, string timer,string chat,string gameBoard);
        void printColoredGame( string page );
		void setGame(void* game);
		void setUsername(string username);
		void printRankOrUserList(string message);

	private:
		string insertElement( InterfacePage page , InputType input , string value , string base);
	};

}

#endif
