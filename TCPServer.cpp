// Lab07_Concurent_TCP_Server_SYNCHRONIZED.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include "winsock2.h"
#include "ws2tcpip.h"
#include "MyThread.h"
#include <vector>
#include <synchapi.h>

#pragma comment(lib, "ws2_32.lib") 

using namespace std;

void main()
{
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        cout << "Couldn't load dll. WSAStartup failed. Error code: " << WSAGetLastError() << endl;
        return;
    }

    SOCKET listenSocket;
    if ((listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == INVALID_SOCKET)
    {
        cout << "Couldn't create listensocket. Error code: " << WSAGetLastError() << endl;
        return;
    }

    sockaddr_in serverAddr;
    int Port = 27095;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(Port);
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
    {
        cout << "Couldn't bind socket. Error code: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        return;
    }

    cout << "Server Started\n";

    if (listen(listenSocket, 2) == SOCKET_ERROR)
    {
        cout << "Listen failed. Error code: " << WSAGetLastError() << endl;
        closesocket(listenSocket);
        return;
    }

    vector<MyThread*> threadlist;
    CRITICAL_SECTION cs;
    InitializeCriticalSection(&cs);

    cout << "Accepting clients...\n";

    while (1)
    {
        SOCKET acceptSocket;
        sockaddr_in clientAddr;
        int m = sizeof(clientAddr);
        if ((acceptSocket = accept(listenSocket, (SOCKADDR*)&clientAddr, &m)) == INVALID_SOCKET)
        {
            cout << WSAGetLastError() << endl;
            cout << "Couldn't create acceptsocket. Error code: " << WSAGetLastError() << endl;
            return;
        }
        cout << "\nNew client connected. ";

        char clientIp[256];
        int clientPort;
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, sizeof(clientIp));
        clientPort = ntohs(clientAddr.sin_port);
        cout << "Client Ip and Port: " << clientIp << " : " << clientPort << endl;

        MyThread* mt = new MyThread(acceptSocket, clientIp, clientPort, &threadlist, &cs);
        threadlist.push_back(mt);
        mt->start();
    }

    if (closesocket(listenSocket) != 0)
    {
        cout << "Couldn't close listensocket. Error code: " << WSAGetLastError() << endl;
        WSACleanup();
        return;
    }

    WSACleanup();
}


