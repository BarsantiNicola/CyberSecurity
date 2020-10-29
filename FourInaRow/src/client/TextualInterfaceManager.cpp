#include "TextualInterfaceManager.h"

namespace client{
	
	TextualInterfaceManager::TextualInterfaceManager(){

		ifstream myfile;
		ifstream myconf;

		string line;

		adj_x=-1;
		adj_y=-1;
		login_page = "";
		main_page = "";
		myfile.open ("src/client/data/login-art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				login_page= login_page+line+"\n";
		myfile.close();
	
		myfile.open ("src/client/data/main_art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				main_page= main_page+line+"\n";
		myfile.close();
	
		myfile.open ("src/client/data/game_art.txt", ios::in );
		if (myfile.is_open())
			while ( getline (myfile,line) )
				game_page= game_page+line+"\n";
		myfile.close();

        myfile.open ("data/screen_size.conf", ios::in );

        if (myfile.is_open()) {
            while ( getline (myfile,line) ){
                if( adj_x == -1 )
                    adj_x = stoi(line);
                else
                    adj_y = stoi(line);
                if(adj_y != -1 )
                    break;
                }
            if( adj_x == -1 || adj_x > 50 || adj_x <0 ) adj_x = 0;
            if( adj_y == -1 || adj_y > 50 || adj_y < 0 ) adj_y = 0;

        }else
            exit(1);

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
	void TextualInterfaceManager::printLoginInterface(){
		string command;
		//execve("tput clear");//da rinserire
                std::cout <<"\033[2J\033[1;1H";
                cout.flush();
		this->printColoredLogin();
		//cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printColoredLogin(){

	    for( int a = 0; a<adj_y; a++ )
	        cout<<endl;

	    cout<<"\033[0;33m"<<login_page.substr(0,2500)<<"\033[0m";
        cout<<"\033[0;31m"<<login_page.substr(2500,324 )<<"\033[0m"<<login_page.substr( 2824, 114 );
        cout<<"\033[0;31m"<<login_page.substr(2938,10 )<<"\033[0m"<<login_page.substr( 2948, 110 );
        cout<<"\033[0;31m"<<login_page.substr(3058 )<<"\033[0m"<<endl;
	    //cout<<login_page.substr( 2591 );
	    cout<<endl;

	}

	void TextualInterfaceManager::printMainInterface(string username,string activeUser,string serverStatus,string matchStatus,string pendingStatus){

		string command;
		string value;
		//execve("tput clear");//da rinserire
                cout<<"\033[2J\033[1;1H";
                cout.flush();
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::USERNAME , username , main_page);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::ACTIVE_USER , activeUser , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::SERVER_STATUS , serverStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::MATCH_STATUS , matchStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::PENDING_SIZE , pendingStatus , value);
                this->username=username;
                this->printColoredMain( value );
		//cout<<"\t# Insert a command:";
		cout.flush();

	}

    void TextualInterfaceManager::printColoredMain(string page){

        for( int a = 0; a<adj_y; a++ )
            cout<<endl;
        
        cout<<"\033[0;33m"<<page.substr(0,665)<<"\033[0m";
        cout<<"\033[0;34m"<<page.substr(665,678 )<<"\033[0m";
        cout<<page.substr(1343,29)<<"\033[0;34m"<<page.substr(1372,36 )<<"\033[0m"<<page.substr( 1408, 27 )<<"\033[0;34m"<<page.substr(1435, 29 )<<"\033[0m";
        cout<<page.substr(1464,29)<<"\033[0;34m"<<page.substr(1493,36 )<<"\033[0m"<<page.substr( 1529, 27 )<<"\033[0;34m"<<page.substr(1556, 29 )<<"\033[0m";
        cout<<page.substr(1585,29)<<"\033[0;34m"<<page.substr(1614,36 )<<"\033[0m"<<page.substr( 1650, 27 )<<"\033[0;34m"<<page.substr(1677, 329 )<<"\033[0m";
        cout<<"\033[0;31m"<<page.substr(2006,245)<<"\033[0m"<<page.substr(2251,115 )<<"\033[31m"<<page.substr( 2366, 6 ) <<"\033[0m";
        cout<<page.substr(2372,115 )<<"\033[31m"<<page.substr( 2487, 6 ) <<"\033[0m";
        cout<<page.substr(2493,115 )<<"\033[31m"<<page.substr( 2608, 6 ) <<"\033[0m";
        cout<<page.substr(2614,115 )<<"\033[31m"<<page.substr( 2729, 6 ) <<"\033[0m";
        cout<<page.substr(2735,115 )<<"\033[31m"<<page.substr( 2850 ) <<"\033[0m";
        //cout<<login_page.substr( 2591 );
        cout<<endl;

    }

	void TextualInterfaceManager::printGameInterface(bool myMove, string timer,string chat,string gameboard){
	
		string command;
                string value;
                string tok;
                //execve("tput clear");//da rinserire
                cout<<"\033[2J\033[1;1H";
                cout.flush();
                value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::TIMER,timer,game_page);
		value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::CHAT,chat,value);
                value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::GAMEBOARD,gameboard,value);
		cout<<value<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();
		cin>>command;
		//return false;
	}

	void TextualInterfaceManager::printColoredGame(string page ){}


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
                                          position = START_GAMEBOARD_POSITION + LOCAL_GAMEBOARD_POSITION +(number_game_row*NUMBER_COLLUMN_FOR_ROW)-(a+1);
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
