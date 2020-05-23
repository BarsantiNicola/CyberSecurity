#include "TextualInterfaceManager.h"

namespace client{
	
	TextualInterfaceManager::TextualInterfaceManager(){

		ifstream myfile;
		string line;
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
	}

	void TextualInterfaceManager::printLoginInterface(string message){
		string command;
		system("tput clear");
		cout<<login_page<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();

	}

	void TextualInterfaceManager::printMainInterface(string message){

		string command;
		string value;
		system("tput clear");
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::USERNAME , "Gianluca Tumminelli" , main_page);
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::ACTIVE_USER , "98" , value );
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::SERVER_STATUS , "ONLINE" , value );
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::MATCH_STATUS , "NONE" , value );
		value = insertElement(InterfacePage::MAIN_PAGE_0, InputType::PENDING_SIZE , "3" , value );
		cout<<value<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();

	}

	bool TextualInterfaceManager::printGameInterface(bool myMove, string message ){
	
		string command;
		system("tput clear");
		cout<<game_page<<endl;
		cout<<"\t# Insert a command:";
		cout.flush();
		cin>>command;
		return false;
	}

	string TextualInterfaceManager::insertElement( InterfacePage page , InputType input , string elem , string base ){
	
		int position = -1;
		switch( page ){
			case InterfacePage::MAIN_PAGE_0:
				switch( input ){
					case InputType::USERNAME: 
						position = 723;
						break;
					case InputType::SERVER_STATUS:
						position = 836;
						break;
					case InputType::ACTIVE_USER:
						position = 939;
						break;
					case InputType::PENDING_SIZE:
						position = 800;
						break;
					case InputType::MATCH_STATUS:
						position = 899;
						break;
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
			}
		}
		return base;
	}
	
}
