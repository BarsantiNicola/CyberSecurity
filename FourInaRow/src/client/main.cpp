#include "TextualInterfaceManager.h"
#include "../utility/Logger.h"

int main(int argc, char **argv)
{
	utility::Logger base(utility::NO_VERBOSE);
	utility::Logger verbose(utility::VERBOSE);
	utility::Logger vverbose(utility::VERY_VERBOSE);
	utility::threshold = utility::VERBOSE;
	
	base<<"ciao ciao";
	verbose<<"ciao ciao";
	vverbose<<"ciao ciao";
	cout<<endl;
	//client::TextualInterfaceManager p;
	//string command;
//	p.printLoginInterface("");
	//p.printMainInterface("");
//	p.printGameInterface(false,"");
	//cin>>command;
	return 0;
}

