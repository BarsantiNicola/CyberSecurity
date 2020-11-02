#include "TextualInterfaceManager.h"

namespace client{
	
	TextualInterfaceManager::TextualInterfaceManager(){

		ifstream myfile;
		ifstream myconf;

		string line;
        for(int a = 0; a<10;a++)
            for(int b = 0; b<50;b++)
                chatLines[a][b] = ' ';
        last = false;
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
    bool TextualInterfaceManager::setChat( string username, char message[], int len ){

	    if( len > 200 || username.length() > 200 ) return false;
	    if( !last ){
	        for( int a = 0; a<5; a++ )
	            for( int b = 0; b<50; b++ )
	            chatLines[a][b] = ' ';
	        for( int a = 0; a<username.length(); a++ )
	            chatLines[0][a] = username[a];
	        for( int a = 0; a<len; a++ )
	            chatLines[1+a/50][a%50] = message[a];
	        last = true;
	    }else{
	        for( int a = 0; a<5; a++ )
	            for( int b= 0; b<50; b++ )
	                chatLines[a][b] = chatLines[5+a][b];
            for( int a = 5; a<10; a++ )
                for( int b = 0; b<50; b++ )
                    chatLines[a][b] = ' ';
            for( int a = 0; a<username.length(); a++ )
                chatLines[5][a] = username[a];
            for( int a = 0; a<len; a++ )
                chatLines[6+a/50][a%50] = message[a];
	    }

	    return true;
	}
	void TextualInterfaceManager::printLoginInterface(){
		string command;
		//execve("tput clear");//da rinserire
                std::cout <<"\033[2J\033[1;1H";
                cout.flush();
		this->printColoredGame(game_page);
		//cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printColoredLogin(){

	    for( int a = 0; a<adj_y; a++ )
	        cout<<endl;

	    for( int a = 0; a<36; a++ ) {

	        for( int b = 0; b<adj_x; b++)
	            cout<<" ";
            switch (a) {

                case 29:
                case 35:
                    cout << "\033[0;31m" << login_page.substr(a * 121, 121) << "\033[0m";
                    break;

                case 30:
                case 31:
                case 32:
                case 33:
                case 34:
                    cout << "\033[0;31m" << login_page.substr(a * 121, 3) << "\033[0m"
                         << login_page.substr(a * 121 + 3, 115) << "\033[0;31m" << login_page.substr(a * 121 + 118, 3)
                         << "\033[0m";
                    break;

                default:

                    cout << "\033[0;33m" << login_page.substr(a * 121, 121) << "\033[0m";
                    break;
            }
        }
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

        for( int a = 0; a<34; a++ ) {

            for( int b = 0; b<adj_x; b++)
                cout<<" ";
            switch (a) {

                case 14:
                case 15:
                case 16:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m"<< page.substr(a * 121+9, 29 );
                    cout <<"\033[0;34m"<<page.substr(a*121+38,36)<<"\033[0m"<< page.substr(a * 121+74, 27 )<<"\033[0;34m"<<page.substr(a*121+101,20 )<<"\033[0m";
                    break;
                case 12:
                case 13:
                case 17:
                case 18:
                    cout << "\033[0;34m" << page.substr(a * 121, 121) << "\033[0m";
                    break;

                case 27:
                case 28:
                case 29:
                case 30:
                case 31:
                    cout << "\033[0;31m" << page.substr(a * 121, 3) << "\033[0m"
                         << page.substr(a * 121 + 3, 115) << "\033[0;31m" << page.substr(a * 121 + 118, 3)
                         << "\033[0m";
                    break;

                case 25:
                case 26:
                case 32:
                case 33:
                    cout << "\033[0;31m" << page.substr(a * 121, 121) << "\033[0m";
                    break;

                default:
                    cout << "\033[0;33m" << page.substr(a * 121, 121) << "\033[0m";
                    break;
            }
        }
        cout<<endl;

    }

	void TextualInterfaceManager::printGameInterface(bool myMove, string timer,string chat,string gameboard){
	
		string command;
                string value;
                string tok;
                //execve("tput clear");//da rinserire
                cout<<"\033[2J\033[1;1H";
                cout.flush();
                //value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::TIMER,timer,game_page);
		value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::CHAT,chat,game_page );
                value=insertElement(InterfacePage::MATCH_PAGE_0,InputType::GAMEBOARD,gameboard,value);
		this->printColoredGame( value );
		cout<<"\t# Insert a command:";
		cout.flush();
		//cin>>command;
		//return false;
	}

	void TextualInterfaceManager::printColoredGame(string page ){

        for( int a = 0; a<adj_y; a++ )
            cout<<endl;

        for( int a = 0; a<35; a++ ) {

            for( int b = 0; b<adj_x; b++)
                cout<<" ";

            switch (a) {

                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                    cout << "\033[0;33m" << page.substr(a * 121, 121) << "\033[0m";
                    break;

                case 9:
                    cout<<page.substr(a * 121, 121);
                    break;

                case 10:
                    cout << "\033[0;34m" << page.substr(a * 121, 63)<<"\033[0m"<< page.substr(a * 121+63,  58);
                    break;

                case 11:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m"<< page.substr(a * 121+9, 52 );
                    cout <<"\033[0;34m"<<page.substr(a*121+61,60)<<"\033[0m";
                    break;


                case 23:
                    cout << "\033[0;34m" << page.substr(a * 121, 121) << "\033[0m";
                    break;

                case 29:
                case 30:
                case 31:
                case 32:
                    cout << "\033[0;31m" << page.substr(a * 121, 3) << "\033[0m"
                         << page.substr(a * 121 + 3, 115) << "\033[0;31m" << page.substr(a * 121 + 118, 3)
                         << "\033[0m";
                    break;

                case 27:
                case 28:
                case 33:
                case 34:
                    cout << "\033[0;31m" << page.substr(a * 121, 121) << "\033[0m";
                    break;
                case 12:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0;36m"; this->printLine(a) /*page.substr(a * 121+9, 52 )*/;
                    cout <<"\033[0;34m"<<page.substr(a*121+61,24)<<"\033[0m";
                    for( int x = 0;x<33;x++)
                        switch( page[a*121+85+x]) {
                            case 'O':
                                cout << "\033[0;34mO\033[0m";
                            case 'X':
                                cout << "\033[0;31mO\033[0m";
                            default:
                                cout << page[a * 121 + 85 + x];
                        }
                    cout<<"\033[0;34m"<<page.substr(a*121+118,3 )<<"\033[0m";
                    break;
                case 17:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0;36m"; this->printLine(a) /*page.substr(a * 121+9, 52 )*/;
                    cout <<"\033[0;34m"<<page.substr(a*121+61,24)<<"\033[0m";
                    for( int x = 0;x<33;x++)
                        switch( page[a*121+85+x]) {
                            case 'O':
                                cout << "\033[0;34mO\033[0m";
                            case 'X':
                                cout << "\033[0;31mO\033[0m";
                            default:
                                cout << page[a * 121 + 85 + x];
                        }
                    cout<<"\033[0;34m"<<page.substr(a*121+118,3 )<<"\033[0m";
                    break;

                default:
                    if( a > 12 ) {
                        cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m";
                        this->printLine(a) /*page.substr(a * 121+9, 52 )*/;
                        cout << "\033[0;34m" << page.substr(a * 121 + 61, 24) << "\033[0m";
                        for (int x = 0; x < 33; x++)
                            switch (page[a * 121 + 85 + x]) {
                                case 'O':
                                    cout << "\033[0;34mO\033[0m";
                                case 'X':
                                    cout << "\033[0;31mO\033[0m";
                                default:
                                    cout << page[a * 121 + 85 + x];
                            }
                        cout << "\033[0;34m" << page.substr(a * 121 + 118, 3) << "\033[0m";
                    }else{
                        cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m"<<page.substr(a * 121+9, 52 );
                        cout << "\033[0;34m" << page.substr(a * 121 + 61, 24) << "\033[0m";
                        for (int x = 0; x < 33; x++)
                            switch (page[a * 121 + 85 + x]) {
                                case 'O':
                                    cout << "\033[0;34mO\033[0m";
                                case 'X':
                                    cout << "\033[0;31mO\033[0m";
                                default:
                                    cout << page[a * 121 + 85 + x];
                            }
                        cout << "\033[0;34m" << page.substr(a * 121 + 118, 3) << "\033[0m";
                    }
                    break;
       //
            }
        }
        cout<<endl;

	}

	void TextualInterfaceManager::printLine( int line ){
	    line-=12;
	    if( line <10 ) {
            cout << ' ';
            for (int a = 0; a < 50; a++)
                cout << chatLines[line][a];
            cout << ' ';
        }else
	        for( int a = 0; a<52; a++ )
	            cout<<' ';

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
                                          position = START_GAMEBOARD_POSITION +(NUMBER_COLLUMN_FOR_ROW-LOCAL_GAMEBOARD_POSITION)+LOCAL_GAMEBOARD_POSITION +(number_game_row*NUMBER_COLLUMN_FOR_ROW)-(a+1);
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
