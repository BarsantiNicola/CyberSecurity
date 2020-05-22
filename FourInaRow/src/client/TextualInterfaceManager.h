
#ifndef TEXTUAL_INTERFACE_MANAGER
#define TEXTUAL_INTERFACE_MANAGER
#include <iostream>
#include <fstream>
using namespace std;

namespace client{
	

	enum class InterfacePage{
		MAIN_PAGE_0
	};

	enum class InputType{
		USERNAME,
		SERVER_STATUS,
		ACTIVE_USER,
		PENDING_SIZE,
		MATCH_STATUS
	};

	class TextualInterfaceManager{
	
	private:
		string login_page;
		string main_page;
		string game_page;
		string username;
		void* game;
	
	public:
		TextualInterfaceManager();
		void printLoginInterface(string message);
		void printMainInterface(string message);
		bool printGameInterface(bool myMove,string message);
		/*void setGame(void* game);
		void setUsername(string username);
		void printRank(string message);
		void printUserList(string message);*/

	private:
		string insertElement( InterfacePage page , InputType input , string value , string base );
	};

}

#endif