#include "MyThread.h"
#include <iostream>
#include <fstream>

using namespace std;

#define BUFLEN 8192

MyThread::MyThread(SOCKET s, char* IPaddr, int Port, vector<MyThread*>* th, CRITICAL_SECTION* cs)
{
    this->acceptSocket = s;
    this->IP = IPaddr;
    this->Port = Port;
    this->username = "";
    this->loggedIn = false;
    this->isReceivingAllowed = false;
    this->isSendingAllowed = false;
    this->threads = th;
    this->cs = cs;
}

SOCKET MyThread::getSocket()
{
    return this->acceptSocket;
}

void MyThread::run()
{
    while (1)
    {
        char recvBuf[BUFLEN];
        string rbuf = "";
        int iRecv = recv(this->getSocket(), recvBuf, sizeof(recvBuf), 0);
        if (iRecv == SOCKET_ERROR || iRecv == 0)
        {
            this->loggedIn = false;

            EnterCriticalSection(cs);
            sendClientList();
            LeaveCriticalSection(cs);
            if (closesocket(this->getSocket()) != 0)
            {
                cout << "Couldn't close acceptsocket. Error code: " << WSAGetLastError() << endl;
            }
            else
            {
                cout << "Client " << this->username << " with IP: " << this->IP << ":" << this->Port << " Disconnected\n";
            }
            break;
        }

        cout << "\nReceiving Data...\t - " << iRecv << endl;

        rbuf.append(recvBuf, iRecv);
        cout << rbuf << endl;

        if (getMessageType(rbuf) == "7")
        {
            if (!isMessageFromValidUser(rbuf))
            {
                cout << "Message received from invalid user. Package forwarding is not allowed!!\n";
                continue;
            }
            if (!isMessageToValidUser(rbuf))
            {
                cout << "Message is being sent to invalid user. Package forwarding is not allowed!!\n";
                continue;
            }
            EnterCriticalSection(cs);
            string username = getUsernameToSendPrivate(rbuf);
            string fromusername = getUsernameFromReceivePrivate(rbuf);
            //Sending the file header to the receiver
            for (size_t i = 0; i < threads->size(); ++i)
            {
                if (!threads->at(i)->isExited())
                {
                    if (threads->at(i)->username == username)
                    {
                        threads->at(i)->isReceivingAllowed = false;
                        threads->at(i)->isSendingAllowed = false;
                        cout << "\nSending Data...\n";
                        int iSend;
                        if ((iSend = send(threads->at(i)->acceptSocket, rbuf.c_str(), iRecv, 0)) == SOCKET_ERROR)
                        {
                            cout << "Failed sending Private Data At Client: " << threads->at(i)->IP
                                << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                            break;
                        }

                        if (iSend == iRecv)
                        {
                            cout << "FILE HEADERDATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                << threads->at(i)->IP << " : " << threads->at(i)->Port << "\n" << rbuf << endl;
                        }
                        else
                        {
                            cout << "Couldn't send all the Fileheader data At Client:" << threads->at(i)->username << " - IP: "
                                << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                        }
                    }
                }
                else
                {
                    MyThread* temp = threads->at(i);
                    threads->erase(threads->begin() + i);
                    delete temp;
                }
            }
            // restrict sending and receiving other types of message at sender client
            for (size_t i = 0; i < threads->size(); ++i)
            {
                if (!threads->at(i)->isExited())
                {
                    if (threads->at(i)->username == fromusername)
                    {
                        threads->at(i)->isSendingAllowed = false;
                        threads->at(i)->isReceivingAllowed = false;
                    }
                }
            }
            LeaveCriticalSection(cs);
            while (1)
            {
                //receiving file parts from the sender client
                int iRecvTemp = recv(this->getSocket(), recvBuf, sizeof(recvBuf), 0);
                if (iRecvTemp == SOCKET_ERROR || iRecvTemp == 0)
                {
                    cout << "ERR_SENDER_DISCONNECTED";
                    for (size_t i = 0; i < threads->size(); ++i)
                    {
                        if (!threads->at(i)->isExited())
                        {
                            if (threads->at(i)->username == username)
                            {
                                cout << "\nSending Errormessage for not receving all parts of the file...\n";
                                int iSend;
                                strcpy_s(recvBuf, "*ERR*");
                                if ((iSend = send(threads->at(i)->acceptSocket, recvBuf, sizeof(recvBuf), 0)) == SOCKET_ERROR)
                                {
                                    cout << "Failed sending Errormessage for not receving all parts of the file At Client: "
                                        << threads->at(i)->IP << " : " << threads->at(i)->Port 
                                        << ". Error code: " << WSAGetLastError() << endl;
                                    break;
                                }

                                if (iSend == sizeof(recvBuf))
                                {
                                    cout << "Errormessage for not receving all parts of the file SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                        << threads->at(i)->IP << " : " << threads->at(i)->Port << " iSend: " << iSend << "\n" << endl;
                                }
                                else
                                {
                                    cout << "Couldn't send all the Errormessage for not receving all parts of the file At Client:" << threads->at(i)->username << " - IP: "
                                        << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                                }
                            }
                        }
                    }
                    cout << "BREAKED 154 ...\n";
                    //Restore the laws to send and receive data at sender and receiver clients
                    EnterCriticalSection(cs);
                    for (size_t i = 0; i < threads->size(); ++i)
                    {
                        if (!threads->at(i)->isExited())
                        {
                            if (threads->at(i)->username == username)
                            {
                                threads->at(i)->isReceivingAllowed = true;
                                threads->at(i)->isSendingAllowed = true;
                            }
                            if (threads->at(i)->username == fromusername)
                            {
                                threads->at(i)->isSendingAllowed = true;
                                threads->at(i)->isReceivingAllowed = true;
                            }
                        }
                    }
                    Sleep(3000);
                    sendClientList();
                    LeaveCriticalSection(cs);
                    break;
                }
                string temp_s = "";
                temp_s.append(recvBuf, iRecvTemp);
                cout << "SENDING FILEPART\t ";
                //sending file parts to the receiver client
                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (!threads->at(i)->isExited())
                    {
                        if (threads->at(i)->username == username)
                        {
                            cout << "\nSending Data...\n";
                            int iSend;
                            if ((iSend = send(threads->at(i)->acceptSocket, recvBuf, iRecvTemp, 0)) == SOCKET_ERROR)
                            {
                                cout << "Failed sending Private Data At Client: " << threads->at(i)->IP
                                    << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                                cout << "ERR_RECEIVER_DISCONNECTED";
                                continue;
                            }

                            if (iSend == iRecvTemp)
                            {
                                cout << "PRIVATE FILEDATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << " iRecv: " << iRecvTemp << "\n" << endl;
                            }
                            else
                            {
                                cout << "Couldn't send all the private filedata At Client:" << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                            }
                        }
                    }
                }

                if (has_suffix(temp_s, "*EOF*") == true)
                {
                    cout << "Exited from file sending....\n";
                    EnterCriticalSection(cs);
                    for (size_t i = 0; i < threads->size(); ++i)
                    {
                        //Restore the laws to send and receive data at sender and receiver clients
                        if (!threads->at(i)->isExited())
                        {
                            if (threads->at(i)->username == username)
                            {
                                threads->at(i)->isReceivingAllowed = true;
                                threads->at(i)->isSendingAllowed = true;
                            }
                            if (threads->at(i)->username == fromusername)
                            {
                                //Sending alertmessage to the sender that the whole file was sent to the receiver
                                threads->at(i)->isReceivingAllowed = true;
                                threads->at(i)->isSendingAllowed = true;
                                string errormsg = "7\t6\t\t\t2";
                                cout << "\nSending Data..." << strlen(errormsg.c_str()) << endl;
                                int iSend;
                                if ((iSend = send(threads->at(i)->acceptSocket, errormsg.c_str(), strlen(errormsg.c_str()), 0)) == SOCKET_ERROR)
                                {
                                    cout << "Failed sending Private Data At Client: " << threads->at(i)->IP
                                        << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                                    cout << "ERR_RECEIVER_DISCONNECTED";
                                    continue;
                                }

                                if (iSend == strlen(errormsg.c_str()))
                                {
                                    cout << "PRIVATE FILEDATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                        << threads->at(i)->IP << " : " << threads->at(i)->Port << " iSend: " << sizeof(recvBuf) << "\n" << endl;
                                }
                                else
                                {
                                    cout << "Couldn't send all the private filedata At Client:" << threads->at(i)->username << " - IP: "
                                        << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                                }

                            }
                        }
                    }
                    LeaveCriticalSection(cs);
                    break;
                }
            }
            continue;
        }
        else
        {
            int len = rbuf.find("\t");
            int fullDataLength = stoi(rbuf.substr(0, len));
            cout << "fulldatalen:" << fullDataLength << endl;

            while (iRecv < fullDataLength)
            {
                int iRecvTemp = recv(this->getSocket(), recvBuf, sizeof(recvBuf), 0);
                if (iRecvTemp == SOCKET_ERROR || iRecvTemp == 0)
                {
                    this->loggedIn = false;
                    break;
                }
                iRecv += iRecvTemp;
                rbuf.append(recvBuf, iRecvTemp);
            }

            if (isFullMessageReceived(rbuf, iRecv))
            {
                cout << "ALL DATA HAS SUCCESSFULLY RECEIVED!\n";
            }
            else
            {
                cout << "Couldn't receive all data....!";
                continue;
            }
            cout << "Message: " << rbuf << endl;

            /***********************************************************/

            string msgtype = getMessageType(rbuf);

            if (msgtype == "1") //LOGIN
            {
                string temp_username = "";
                string temp_password = "";

                for (int i = 0; i < 4; ++i)
                {
                    int len = rbuf.find("\t"); // erase the length of data, messagetype, from_who and to_whom
                    rbuf = rbuf.erase(0, len + 1);
                }

                int len = rbuf.find("\t");
                temp_username = rbuf.substr(0, len);
                rbuf = rbuf.erase(0, len + 1);

                len = rbuf.find("\t");
                temp_password = rbuf.substr(0, len);

                char login_resp[5] = "E200";
                string new_client = login(temp_username, temp_password);
                int iSend;

                if (new_client == "E404" || new_client == "E403")
                {
                    strcpy_s(login_resp, sizeof(login_resp), new_client.c_str());
                    if ((iSend = send(this->getSocket(), login_resp, sizeof(login_resp), 0)) == SOCKET_ERROR)
                    {
                        cout << "Failed sending Data. Error code: " << WSAGetLastError() << endl;
                        continue;
                    }
                    cout << "Sending login response: " << login_resp << endl;
                    if (closesocket(this->getSocket()) != 0)
                    {
                        cout << "Couldn't close acceptsocket. Error code: " << WSAGetLastError() << endl;
                    }
                    else
                    {
                        cout << "Client " << this->username << " with IP: " << this->IP << ":" << this->Port << " Disconnected\n";
                    }
                    continue;
                }
                else
                {
                    this->username = new_client;
                    this->loggedIn = true;
                    this->isSendingAllowed = true;
                    this->isReceivingAllowed = true;

                    if ((iSend = send(this->getSocket(), login_resp, sizeof(login_resp), 0)) == SOCKET_ERROR)
                    {
                        cout << "Failed sending Data. Error code: " << WSAGetLastError() << endl;
                        continue;
                    }
                    cout << "New Client name::" << new_client << "\nSending login response: " << login_resp << endl;
                    EnterCriticalSection(cs);
                    sendClientList();
                    LeaveCriticalSection(cs);
                }
            }
            else if (msgtype == "2" && this->loggedIn && this->isSendingAllowed) /*SENDING FOR EVERYONE*/
            {
                if (!isMessageFromValidUser(rbuf))
                {
                    cout << "Message received from invalid user. Package forwarding is not allowed!!\n";
                    continue;
                }

                EnterCriticalSection(cs);
                cout << "Entered critical section for sending everyone.\n";

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (threads->at(i)->isExited())
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (!threads->at(i)->isExited())
                    {
                        if (!threads->at(i)->isReceivingAllowed)
                        {
                            continue;
                        }
                        cout << "\nSending Data...\n";
                        int iSend;
                        if ((iSend = send(threads->at(i)->acceptSocket, rbuf.c_str(), fullDataLength, 0)) == SOCKET_ERROR)
                        {
                            cout << "Failed sending Data At Client: " << threads->at(i)->IP
                                << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                            continue;
                        }

                        if (iSend == fullDataLength)
                        {
                            cout << "DATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                << threads->at(i)->IP << " : " << threads->at(i)->Port << "\n" << rbuf << endl;
                        }
                        else
                        {
                            cout << "Couldn't send all the data At Client:" << threads->at(i)->username << " - IP: "
                                << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                        }
                    }
                    else
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }
                LeaveCriticalSection(cs);
                cout << "Left critical section for sending to everyone\n";
            }
            else if (msgtype == "3" && this->loggedIn && this->isSendingAllowed) //SENDING PRIVATE message
            {
                if (!isMessageFromValidUser(rbuf))
                {
                    cout << "Message received from invalid user. Package forwarding is not allowed!!\n";
                    continue;
                }
                if (!isMessageToValidUser(rbuf))
                {
                    cout << "Message is being sent to invalid user. Package forwarding is not allowed!!\n";
                    continue;
                }
                EnterCriticalSection(cs);
                cout << "Entered critical section for sending PRIVATE message.\n";

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (threads->at(i)->isExited())
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }
                string username = getUsernameToSendPrivate(rbuf);

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (!threads->at(i)->isExited())
                    {
                        if (!threads->at(i)->isReceivingAllowed)
                        {
                            continue;
                        }
                        if (threads->at(i)->username == username || threads->at(i)->username == this->username)
                        {
                            cout << "\nSending Data...\n";
                            int iSend;
                            if ((iSend = send(threads->at(i)->acceptSocket, rbuf.c_str(), fullDataLength, 0)) == SOCKET_ERROR)
                            {
                                cout << "Failed sending Private Data At Client: " << threads->at(i)->IP
                                    << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                                continue;
                            }

                            if (iSend == fullDataLength)
                            {
                                cout << "PRIVATE DATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << "\n" << rbuf << endl;
                            }
                            else
                            {
                                cout << "Couldn't send all the private data At Client:" << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                            }
                        }
                    }
                    else
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }
                LeaveCriticalSection(cs);
                cout << "Left critical section for sending PRIVATE message\n";
            }
            else if ((msgtype == "5" || msgtype == "6" || msgtype == "7") && this->loggedIn && this->isSendingAllowed) //SENDING request for accepting file sending
            {
                if (!isMessageFromValidUser(rbuf))
                {
                    cout << "Message received from invalid user. Package forwarding is not allowed!!\n";
                    continue;
                }
                if (!isMessageToValidUser(rbuf))
                {
                    cout << "Message is being sent to invalid user. Package forwarding is not allowed!!\n";
                    continue;
                }
                EnterCriticalSection(cs);
                cout << "Entered critical section for sending PRIVATE message.\n";

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (threads->at(i)->isExited())
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }
                string username = getUsernameToSendPrivate(rbuf);

                for (size_t i = 0; i < threads->size(); ++i)
                {
                    if (!threads->at(i)->isExited())
                    {
                        if (!threads->at(i)->isReceivingAllowed)
                        {
                            continue;
                        }
                        if (threads->at(i)->username == username)
                        {
                            cout << "\nSending Data...\n";
                            int iSend;
                            if ((iSend = send(threads->at(i)->acceptSocket, rbuf.c_str(), fullDataLength, 0)) == SOCKET_ERROR)
                            {
                                cout << "Failed sending Private Data At Client: " << threads->at(i)->IP
                                    << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                                continue;
                            }

                            if (iSend == fullDataLength)
                            {
                                cout << "PRIVATE DATA SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << "\n" << rbuf << endl;
                            }
                            else
                            {
                                cout << "Couldn't send all the private data At Client:" << threads->at(i)->username << " - IP: "
                                    << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                            }
                        }
                    }
                    else
                    {
                        MyThread* temp = threads->at(i);
                        threads->erase(threads->begin() + i);
                        delete temp;
                    }
                }
                LeaveCriticalSection(cs);
                cout << "Left critical section for sending PRIVATE message\n";
            }
        }

    }
}

void MyThread::sendClientList()
{
    string clist = "";
    for (int i = 0; i < threads->size(); ++i)
    {
        if (!threads->at(i)->isExited() && threads->at(i)->loggedIn)
        {
            clist = clist + threads->at(i)->username + ',';
        }
    }
    clist = clist.substr(0, size(clist) - 1); // removing the last comma character
    clist = "4\tServer\tEverybody\t" + clist;
    int len_clist = size(clist) + 1;
    int len_len_clist = size(to_string(len_clist));
    len_clist += len_len_clist;
    clist = to_string(len_clist) + '\t' + clist;
    cout << "ClientList: " << clist << endl;

    for (int i = 0; i < threads->size(); ++i)
    {
        if (!threads->at(i)->isExited())
        {
            if (!threads->at(i)->isReceivingAllowed)
            {
                continue;
            }
            if (threads->at(i)->loggedIn)
            {
                cout << "\nSending Clientlist...\n";
                int iSend;
                if ((iSend = send(threads->at(i)->acceptSocket, clist.c_str(), len_clist, 0)) == SOCKET_ERROR)
                {
                    cout << "Failed!! sending Data At Client: " << threads->at(i)->IP
                        << " : " << threads->at(i)->Port << ". Error code: " << WSAGetLastError() << endl;
                    continue;
                }

                if (iSend == len_clist)
                {
                    cout << "CLIENTLIST SENT SUCCESSFULLY AT CLIENT: " << threads->at(i)->username << " - IP: "
                        << threads->at(i)->IP << " : " << threads->at(i)->Port << "\n" << clist << endl;
                }
                else
                {
                    cout << "Couldn't send all the clientlist At Client:" << threads->at(i)->username << " - IP: "
                        << threads->at(i)->IP << " : " << threads->at(i)->Port << endl;
                }
            }
        }
        else
        {
            MyThread* temp = threads->at(i);
            threads->erase(threads->begin() + i);
            delete temp;
        }
    }
}

bool MyThread::isLoggedIn(string username)
{
    for (int i = 0; i < threads->size(); ++i)
    {
        if (!threads->at(i)->isExited())
        {
            if (threads->at(i)->username == username)
            {
                return true;
            }
        }
        else
        {
            MyThread* temp = threads->at(i);
            threads->erase(threads->begin() + i);
            delete temp;
        }
    }
    return false;
}

string MyThread::login(string username, string password)
{
    string temp_username = "";
    string temp_password = "";
    string user_notfound = "E404";
    string user_already_in = "E403";
    ifstream ifs("users.txt");
    if (!ifs)
    {
        return user_notfound;
    }
    while (!ifs.eof())
    {
        string line;
        getline(ifs, line);

        int len = line.find("\t");
        temp_username = line.substr(0, len);
        line = line.erase(0, len + 1);

        len = line.find("\t");
        temp_password = line.substr(0, len);
        line = line.erase(0, len + 1);

        if (temp_username == username && temp_password == password)
        {
            if (isLoggedIn(temp_username))
            {
                ifs.close();
                return user_already_in;
            }
            ifs.close();
            return temp_username;
        }
    }
    ifs.close();
    return user_notfound;
}

bool MyThread::isMessageFromValidUser(string message)
{
    int len;
    for (int i = 0; i < 2; ++i)
    {
        len = message.find("\t");
        message = message.erase(0, len + 1);  // erase the length of data and package type
    }
    len = message.find("\t");
    string username = message.substr(0, len);

    for (int i = 0; i < threads->size(); ++i)
    {
        if (threads->at(i)->username == username)
        {
            return true;
        }
    }
    return false;
}

bool MyThread::isMessageToValidUser(string message)
{
    int len;
    for (int i = 0; i < 3; ++i)
    {
        len = message.find("\t");
        message = message.erase(0, len + 1);  // erase the length of data and package type and fromUser
    }
    len = message.find("\t");
    string username = message.substr(0, len);

    for (int i = 0; i < threads->size(); ++i)
    {
        if (threads->at(i)->username == username)
        {
            return true;
        }
    }
    return false;
}

string MyThread::getUsernameToSendPrivate(string message)
{
    int len;
    for (int i = 0; i < 3; ++i)
    {
        len = message.find("\t");
        message = message.erase(0, len + 1);  // erase the length of data and package type and fromUser
    }
    len = message.find("\t");
    string username = message.substr(0, len);
    return username;
}

string MyThread::getUsernameFromReceivePrivate(string message)
{
    int len;
    for (int i = 0; i < 2; ++i)
    {
        len = message.find("\t");
        message = message.erase(0, len + 1);  // erase the length of data and package type
    }
    len = message.find("\t");
    string username = message.substr(0, len);
    return username;
}

string getMessageType(string message)
{
    int len = message.find("\t");
    message = message.erase(0, len + 1);  // erase the length of data
    len = message.find("\t");
    string msgtype = message.substr(0, len);
    if (msgtype.length() == 1)
    {
        return msgtype;
    }
    return "z";

}

bool isFullMessageReceived(string message, int msgLength)
{
    try
    {
        int len = message.find("\t");
        string messageLength = message.substr(0, len);
        if (msgLength == stoi(messageLength))
        {
            return true;
        }
    }
    catch (exception e)
    {
        return false;
    }
}

bool has_suffix(const std::string& str, const std::string& suffix)
{
    return str.size() >= suffix.size() && str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}
