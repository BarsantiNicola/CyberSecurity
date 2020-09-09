#include "TextualInterfaceManager.h"

namespace client{
	
	TextualInterfaceManager::TextualInterfaceManager(){

		ifstream myfile;
		string line;
		login_page = "";
		main_page = "";
		myfile.open ("data/login-art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				login_page= login_page+line+"\n";
		myfile.close();
	
		myfile.open ("data/main_art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				main_page= main_page+line+"\n";
		myfile.close();
	
		myfile.open ("data/game_art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				game_page= game_page+line+"\n";
		myfile.close();
	}


       void TextualInterfaceManager::setUsername(string username)
       {
         this->username=username;
       }
       string* TextualInterfaceManager::getUsername()
       {
         return &username;

   
       }
	void TextualInterfaceManager::printLoginInterface(string message){
		string command;
		system("tput clear");
		cout<<login_page<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printMainInterface(string username,string activeUser,string serverStatus,string matchStatus,string pendingStatus){

		string command;
		string value;
		system("tput clear");
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::USERNAME , username , main_page);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::ACTIVE_USER , activeUser , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::SERVER_STATUS , serverStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::MATCH_STATUS , matchStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::PENDING_SIZE , pendingStatus , value);
		cout<<value<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printGameInterface(bool myMove, string timer,string chat,string gameboard){
	
		string command;
                string value;
                string tok;
                system("tput clear");
                value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::TIMER,timer,game_page);
		value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::CHAT,chat,value);
                value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::GAMEBOARD,gameboard,value);
		cout<<value<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();
		cin>>command;
		//return false;
	}

	string TextualInterfaceManager::insertElement( InterfacePage page , InputType input , string elem , string base)
        {
	                int number_game_row=0;
          		int position = -1;
			string stringApp;
	  		switch( page ){
			case InterfacePage::MAIN_PAGE_0:
				switch( input ){
					case InputType::USERNAME: 
						position = USERNAME_POSITION;
						break;
					case InputType::SERVER_STATUS:
						position = SERVERSTATUS_POSITION;
						break;
					case InputType::ACTIVE_USER:
						position = ACTIVE_USERS_POSITION;
						break;
					case InputType::PENDING_SIZE:
						position = PENDING_LIST_SIZE_POSITION;
						break;
					case InputType::MATCH_STATUS:
						position = MATCH_STATUS_POSITION;
						break;
				}
				break;
                       case InterfacePage::MATCH_PAGE_0:
                               switch(input)
				{
                                      case InputType::TIMER:
                                          position=TIME_POSITION;
                                          break;
                                      case InputType::CHAT:
                                          position=START_CHAT_POSITION;
                                          break;

                                      case InputType::GAMEBOARD:
                                          position=START_GAMEBOARD_POSITION;
                                           

                               }
				break;
		}
		if( position == -1 || base.length() < (position+elem.length()) ) return "";
			//  CONTROLLI SU DIMENSIONE INPUT\BASE [TAINTED DATA]
		for( int a = 0; a< elem.length(); a++ ){
			switch( page ){
				case InterfacePage::MAIN_PAGE_0:
					base[position+a] = elem[a];
					break;
                               case InterfacePage::MATCH_PAGE_0:
                                        if(elem[a]=='\n'&& input==InputType::GAMEBOARD)
				        {
                                          ++number_game_row;
                                          position = START_GAMEBOARD_POSITION + (number_game_row*NUMBER_COLLUMN_FOR_ROW)-(a+1);
                                        }
                                        else 
                                        { 
                                          base[position+a] = elem[a];  
                                        }
                                          
					break;
			}
		}
		return base;
	}
	void TextualInterfaceManager::printRankOrUserList(string message)
        {
          cout<<message;
          cout.flush();
        }
}
