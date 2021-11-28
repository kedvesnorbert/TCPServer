#include <limits.h>
#include <windows.h>
#include <vector>
#include <string>

#include "SysThread.h"

using namespace std;

class MyThread : public SysThread
{
private:
	SOCKET acceptSocket;
	char* IP;
	int Port;
	string username;
	bool loggedIn;
	bool isSendingAllowed;
	bool isReceivingAllowed;
	vector<MyThread*>* threads;
	CRITICAL_SECTION* cs;

public:
	MyThread(SOCKET, char*, int, vector<MyThread*>*, CRITICAL_SECTION*);
	SOCKET getSocket();
	virtual void run();
	string login(string, string);
	bool isLoggedIn(string);
	bool isMessageFromValidUser(string);
	bool isMessageToValidUser(string);
	string getUsernameToSendPrivate(string);
	string getUsernameFromReceivePrivate(string);
	void sendClientList();
};

string getMessageType(string);
bool isFullMessageReceived(string, int);
bool has_suffix(const std::string&, const std::string&);


