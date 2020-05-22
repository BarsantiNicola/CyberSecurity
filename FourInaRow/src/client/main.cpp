#include "TextualInterfaceManager.h"

int main(int argc, char **argv)
{
	client::TextualInterfaceManager p;
	string command;
//	p.printLoginInterface("");
	p.printMainInterface("");
//	p.printGameInterface(false,"");
	cin>>command;
	return 0;
}
