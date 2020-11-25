#include "TextualInterfaceManager.h"

namespace client{
	
	TextualInterfaceManager::TextualInterfaceManager(){

		ifstream myfile;
		ifstream myconf;

		string line;
        for(int a = 0; a<10;a++)
            for(int b = 0; b<50;b++)
                chatLines[a][b] = ' ';

        gameBoard = new int*[6];
        for( int a = 0; a<6; a++ )
            gameBoard[a] = new int[7];

        for(int a = 0; a<6; a++ )
            for( int b = 0; b<7; b++)
                gameBoard[a][b] = 0;

        last = true;
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
            myfile.close();
        }else
            while(!setter());

	}


	void TextualInterfaceManager::setUsername(string username)
	{
	    this->username=username;
	}

	string* TextualInterfaceManager::getUsername()
	{

        return &username;

   
    }

    bool TextualInterfaceManager::setGame(int** game){
	    
	    if( !game ) return false;
      /*  if( gameBoard ) {
            for (int a = 0; a < 6; a++)
                delete[] gameBoard[a];
            delete[] gameBoard;
        }*/
	    gameBoard = game;
        return true;

	}

    int TextualInterfaceManager::getXTranslation() {
        return adj_x;
    }

    void TextualInterfaceManager::showTimer( int time ){

	    if( time > 15 || time < 0 ) return;

        resetTimer();
        printf("\033[s");
        printf("\033[%d;%dH",10+adj_y,89+adj_x);
        if( time > 10 )
            cout<<time<<endl;
        else {
            if (time > 5)
                cout << "\033[0;33m" << time << "\033[0m";
            else
                cout << "\033[0;31m" << time << "\033[0m";
        }
        printf("\033[u");

    }

    void TextualInterfaceManager::resetTimer(){

        printf("\033[s");
        printf("\033[%d;%dH",10+adj_y,89+adj_x);
        cout<<"   "<<endl;
        printf("\033[u");

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

    void TextualInterfaceManager::printUserList( char* userList, int len ){

	    string formatter = "";
        for( int b = 0; b<adj_x+45; b++ )
            formatter.append(" ");

        vector<string> users;
        int prev = 0;
        for( int a = 0; a<len; a++ )
            if( userList[a] == '-' || a == len-1 ) {
                userList[a] = '\0';
                users.push_back(string(userList + prev));
                prev = a+1;
            }

        cout<<formatter<< "\033[0;34m"<<"//////////////////////////////"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//"<<"\033[0;33m"<<"        USER LIST         "<<"\033[0;34m"<<"//"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        int extra = 0;
        for( int a= 0; a<users.size(); a++ ){
            cout<<formatter<< "\033[0;34m"<<"//  "<< "\033[0m"<<users[a];
            extra = 22-users[a].length();
            for( int b = 0; b<extra; b++ )
	                cout<<' ';
            cout<< "\033[0;34m"<<"  //\n"<< "\033[0m";

	    }

	    if( users.size() == 0 )
            cout<<formatter<< "\033[0;34m"<<"//"<< "\033[0m"<<"    NO USERS AVAILABLE    "<< "\033[0;34m"<<"//"<< "\033[0m"<<'\n';
	    else
            users.clear();

        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//////////////////////////////\n"<< "\033[0m"<<'\n';


	}

    void TextualInterfaceManager::printRankList( char* rankList, int len, bool print ){


        string formatter = "";
        for( int b = 0; b<adj_x+28; b++ )
            formatter.append(" ");

        cout << formatter << "\033[0;34m" << "//////////////////////////////////////////////////////////////"
                 << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//                                                          //"
                 << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//" << "\033[0;33m"
                 << "                          RANK LIST                       " << "\033[0;34m" << "//" << "\033[0m"
                 << '\n';
        cout << formatter << "\033[0;34m" << "//                                                          //"
                 << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//////////////////////////////////////////////////////////////"
                 << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//" << "\033[0;35m" << "    USERNAME    " << "\033[0;34m" << "//"
                 << "\033[0;35m" << "  WON  " << "\033[0;34m" << "//" << "\033[0;35m" << "  LOST  " << "\033[0;34m" << "//"
                 << "\033[0;35m" << "  TIED  " << "\033[0;34m" << "//" << "\033[0;35m" << "   TOTAL   " << "\033[0;34m"
                 << "//" << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//////////////////////////////////////////////////////////////"
                 << "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//                //       //        //        //           //"
                 << "\033[0m" << '\n';

        string username;
        string app;
        Statistic stat;
        int count = 0;
        int prev = 0;
        int extra;

        for( int a =0; a<len; a++ )
            if( rankList[a] == ' ' || rankList[a] == '\n' ){
                rankList[a] = '\0';
                switch(count){
                    case 0:
                        username = string(rankList+prev);
                        count++;
                        break;
                    case 1:
                        stat.won = stoi(string(rankList+prev));
                        count++;
                        break;
                    case 2:
                        stat.lose = stoi( string(rankList+prev));
                        count++;
                        break;
                    case 3:
                        stat.tie = stoi( string(rankList+prev));

                        cout<<formatter<< "\033[0;34m"<<"//    "<< "\033[0m";
                        extra = 8-username.length();
                        cout<<username;
                        for( int a = 0; a<extra; a++ )
                            cout<<" ";

                        cout<<"\033[0;34m"<<"    //  "<<"\033[0m";
                        app = to_string( stat.won );
                        extra = 3-app.length();
                        cout<<app;
                        for( int a = 0; a<extra; a++ )
                            cout<<" ";

                        cout<<"\033[0;34m"<<"  //  "<<"\033[0m";
                        app = to_string( stat.lose );
                        extra = 4-app.length();
                        cout<<app;
                        for( int a = 0; a<extra; a++ )
                            cout<<" ";

                        cout<<"\033[0;34m"<<"  //   "<<"\033[0m";
                        app = to_string( stat.tie );
                        extra = 5-app.length();
                        cout<<app;
                        for( int a = 0; a<extra; a++ )
                            cout<<" ";

                        cout<<"\033[0;34m"<<"//    "<<"\033[0m";
                        app = to_string( stat.won+stat.lose+stat.tie );
                        extra = 6-app.length();
                        cout<<app;
                        for( int a = 0; a<extra; a++ )
                            cout<<" ";

                        cout<<"\033[0;34m"<<" //"<< "\033[0m"<<'\n';

                        stat = {0,0,0};
                        count = 0;
                        break;

                    default:
                        break;
                }

                prev = a+1;

            }

            cout << formatter << "\033[0;34m" << "//                //       //        //        //           //"
                 << "\033[0m" << '\n';
            cout << formatter << "\033[0;34m" << "//////////////////////////////////////////////////////////////\n"
                 << "\033[0m" << '\n';
	}

    void TextualInterfaceManager::printUserPending( vector<string> users ){

        string formatter = "";
        for( int b = 0; b<adj_x+45; b++ )
            formatter.append(" ");

        cout<<formatter<< "\033[0;34m"<<"//////////////////////////////"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//"<<"\033[0;33m"<<"      PENDING LIST        "<<"\033[0;34m"<<"//"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        int extra = 0;
        for( int a= 0; a<users.size(); a++ ){
            cout<<formatter<< "\033[0;34m"<<"//  "<< "\033[0m"<<users[a];
            extra = 22-users[a].length();
            for( int b = 0; b<extra; b++ )
                cout<<' ';
            cout<< "\033[0;34m"<<"  //\n"<< "\033[0m";

        }

        if( users.size() == 0 )
            cout<<formatter<< "\033[0;34m"<<"//"<< "\033[0m"<<"     NO PENDANT USERS      "<< "\033[0;34m"<<"//"<< "\033[0m"<<'\n';
        else
            users.clear();

        cout<<formatter<< "\033[0;34m"<<"//                          //"<< "\033[0m"<<'\n';
        cout<<formatter<< "\033[0;34m"<<"//////////////////////////////\n"<< "\033[0m"<<'\n';

    }

    void TextualInterfaceManager::printMessage( string message ){

        string formatter = "";
        for( int b = 0; b<adj_x+8; b++ )
            formatter.append(" ");

        if( message.length() >96 )
            cout<<"--> [TextualInterface][printMessage] Warning, function admits message up to 54 character. Reduce dimension"<<'\n';

        int extra = 0;
        cout << formatter << "\033[0;34m" << "////////////////////////////////////////////////////////////////////////////////////////////////////////"<< "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//                                                                                                    //"<< "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "//  "<<"\033[0m";
        if( message.length() > 96 )
            cout<<message.substr(0,96)<< "\033[0;34m" <<"  //"<< "\033[0m" << '\n';
        else{

            extra = 96-message.length();
            cout<<message;
            for( int a = 0; a<extra; a++ )
                cout<<' ';
            cout<< "\033[0;34m" <<"  //"<< "\033[0m" << '\n';

        }
        cout << formatter << "\033[0;34m" << "//                                                                                                    //"<< "\033[0m" << '\n';
        cout << formatter << "\033[0;34m" << "////////////////////////////////////////////////////////////////////////////////////////////////////////\n"<< "\033[0m" << '\n';


	}
	void TextualInterfaceManager::printLoginInterface(){

        execCommand( CLEAR );
		this->printColoredLogin();
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

		string value;
        execCommand( CLEAR );
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::USERNAME , username , main_page);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::ACTIVE_USER , activeUser , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::SERVER_STATUS , serverStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::MATCH_STATUS , matchStatus , value);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::PENDING_SIZE , pendingStatus , value);
		this->username=username;
		this->printColoredMain( value );
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
            }
        }
        cout<<endl;

    }

	void TextualInterfaceManager::printGameInterface(bool myMove, string timer,string chat,string gameboard){

        execCommand(CLEAR);
		this->printColoredGame( game_page );
		cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printColoredGame(string page ){
        int col = 0;
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

                case 11:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m"<< page.substr(a * 121+9, 52 );
                    cout <<"\033[0;34m"<<page.substr(a*121+61,60)<<"\033[0m";
                    break;


                case 23:
                case 24:
                case 10:
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
                            case '+':
                                switch( gameBoard[(a-12)/2][col]){
                                    case 1:
                                        cout << "\033[0;34mO\033[0m";
                                        break;
                                    case 2:
                                        cout << "\033[0;31mO\033[0m";
                                        break;
                                    default:
                                        cout<<' ';

                                }
                                col++;
                                break;
                            default:
                                cout << page[a * 121 + 85 + x];
                        }
                    col = 0;
                    cout<<"\033[0;34m"<<page.substr(a*121+118,3 )<<"\033[0m";
                    break;
                case 17:
                    cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0;36m"; this->printLine(a) /*page.substr(a * 121+9, 52 )*/;
                    cout <<"\033[0;34m"<<page.substr(a*121+61,24)<<"\033[0m";
                    for( int x = 0;x<33;x++)
                        switch( page[a*121+85+x]) {
                            case '+':
                                switch( gameBoard[(a-12)/2][col]){
                                    case 1:
                                        cout << "\033[0;34mO\033[0m";
                                        break;
                                    case 2:
                                        cout << "\033[0;31mO\033[0m";
                                        break;
                                    default:
                                        cout<<' ';
                                }
                                col++;
                                break;
                            default:
                                cout << page[a * 121 + 85 + x];
                        }
                    col = 0;
                    cout<<"\033[0;34m"<<page.substr(a*121+118,3 )<<"\033[0m";
                    break;

                default:
                    if( a > 10 ) {
                        cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m";
                        this->printLine(a) /*page.substr(a * 121+9, 52 )*/;
                        cout << "\033[0;34m" << page.substr(a * 121 + 61, 24) << "\033[0m";
                        for( int x = 0;x<33;x++)
                            switch( page[a*121+85+x]) {
                                case '+':
                                    switch( gameBoard[(a-12)/2][col]){

                                        case 1:
                                            cout << "\033[0;34mO\033[0m";
                                            break;
                                        case 2:
                                            cout << "\033[0;31mO\033[0m";
                                            break;
                                        default:
                                            cout<<' ';
                                    }
                                    col++;
                                    break;
                                default:
                                    cout << page[a * 121 + 85 + x];
                            }
                        col = 0;
                        cout << "\033[0;34m" << page.substr(a * 121 + 118, 3) << "\033[0m";
                    }else{
                        cout << "\033[0;34m" << page.substr(a * 121, 9) << "\033[0m"<<page.substr(a * 121+9, 52 );
                        cout << "\033[0;34m" << page.substr(a * 121 + 61, 24) << "\033[0m";
                        for( int x = 0;x<33;x++)
                            switch( page[a*121+85+x]) {
                                case '+':
                                    switch( gameBoard[(a-12)/2][col]){
                                        case 1:
                                            cout << "\033[0;34mO\033[0m";
                                            break;
                                        case 2:
                                            cout << "\033[0;31mO\033[0m";
                                            break;
                                        default:
                                            cout<<' ';
                                    }
                                    col++;
                                    break;
                                default:
                                    cout << page[a * 121 + 85 + x];
                            }
                        col = 0;
                        cout << "\033[0;34m" << page.substr(a * 121 + 118, 3) << "\033[0m";
                    }
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

    void TextualInterfaceManager::resetChat(){

	    for( int a = 0; a<10; a++ )
	        for( int b=0; b<50; b++ )
	            chatLines[a][b] = ' ';

	}

    void TextualInterfaceManager::resetGameboard(){

	    for( int a = 0; a<7; a++ )
	        for( int b = 0; b<6;b++)
	            gameBoard[a][b] = 0;

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

    bool TextualInterfaceManager::setter(){
	    execCommand(CLEAR);
	    ofstream out;
	    printColoredLogin();
	    for( int a = 0; a<adj_x; a++ )
	        cout<<' ';
	    cout<<"Use the arrows to center the page or press Enter to complete the interface setting"<<endl;
        execCommand(RAW);
        char input = getchar();
        // Reset terminal to normal "cooked" mode
        execCommand(COOKED);
	    switch(input){
	        case 13:

                out.open ("data/screen_size.conf", ios::out );
                if (out.is_open()) {
                    out << adj_x<<endl;
                    out << adj_y<<endl;
                }
                out.close();
                return true;

	        case 65:
	            if( adj_y > 0 ) adj_y--;
	            break;
	        case 66:
	            if( adj_y < 20 ) adj_y++;
	            break;
	        case 67:
	            if( adj_x < 50 ) adj_x++;
	            break;
	        case 68:
	            if( adj_x > 0 ) adj_x--;
	            break;
	        default:
	            cout<<"Bad input"<<endl;
	    }
	    return false;
	}

    void TextualInterfaceManager::execCommand( Command command ){

        int ret;
        char **args = new char*[3];
        for( int a = 0; a<3; a++ )
            args[a] = nullptr;

        switch( command ){
            case CLEAR:
                args[0] = (char*)"/bin/clear";
                break;
            case RAW:
                args[0] = (char*)"/bin/stty";
                args[1] = (char*)"raw";
                break;
            case COOKED:
                args[0] = (char*)"/bin/stty";
                args[1] = (char*)"cooked";
                break;
            default:
                return;

        }

        if (fork())
            wait(&ret);
        else {
            execv( args[0], args );
            exit(1);
        }
    }

}
