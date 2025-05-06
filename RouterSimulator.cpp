#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <optional>
#include <cstdint>
#include <stdexcept>

using namespace std;

// ------------------------- Utilities -------------------------
// Konwersja adresu IP (w formacie "x.x.x.x") na liczbę 32-bitową
uint32_t ipToUint(const string& ip) {
    int parts[4];
    if (sscanf(ip.c_str(), "%d.%d.%d.%d", &parts[0], &parts[1], &parts[2], &parts[3]) != 4) {
        throw invalid_argument("Nieprawidłowy format adresu IP: " + ip + ". Poprawny przykład: 192.168.0.1");
    }
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
}

// Funkcja generująca maskę sieciową na podstawie prefiksu
uint32_t maskFromPrefix(int prefix) {
    if (prefix < 0 || prefix > 32)
        throw invalid_argument("Nieprawidłowa długość prefiksu. Dozwolony zakres: 0-32.");
    return prefix == 0 ? 0 : (0xFFFFFFFF << (32 - prefix));
}

// ------------------------- IPAddress -------------------------
// Klasa reprezentująca adres IP
class IPAddress {
    uint32_t addr;
    int prefix;
public:
    // Konstruktor z parametrem CIDR (adres IP + prefiks)
    explicit IPAddress(const string& cidr) {
        size_t slash = cidr.find('/');
        string ip = cidr.substr(0, slash);
        prefix = (slash == string::npos ? 32 : stoi(cidr.substr(slash + 1)));
        addr = ipToUint(ip) & maskFromPrefix(prefix);
    }

    bool matches(const IPAddress& other) const {
        uint32_t mask = maskFromPrefix(prefix);
        return (other.addr & mask) == addr;
    }

    int getPrefix() const { return prefix; }

    string toString() const {
        ostringstream oss;
        oss << ((addr >> 24) & 0xFF) << '.' << ((addr >> 16) & 0xFF) << '.' << ((addr >> 8) & 0xFF) << '.' << (addr & 0xFF) << '/' << prefix;
        return oss.str();
    }

    bool operator==(const IPAddress& other) const {
        return addr == other.addr && prefix == other.prefix;
    }
};

namespace std {
    template <>
    struct hash<IPAddress> {
        size_t operator()(const IPAddress& ip) const {
            return hash<string>()(ip.toString());
        }
    };
}

// ------------------------- Route -------------------------
// Klasa reprezentująca trasę w tablicy routingu
class Route {
    IPAddress network;
    IPAddress gateway;
    int metric;
public:
    Route(const IPAddress& net, const IPAddress& gw, int met)
        : network(net), gateway(gw), metric(met) {}

    const IPAddress& getNetwork() const { return network; }
    const IPAddress& getGateway() const { return gateway; }
    int getMetric() const { return metric; }

    bool matches(const IPAddress& addr) const {
        return network.matches(addr);
    }

    string toString() const {
        ostringstream oss;
        oss << "Sieć: " << network.toString()
            << ", Brama: " << gateway.toString()
            << ", Metryka: " << metric;
        return oss.str();
    }
};

// ------------------------- RoutingTable -------------------------
// Klasa reprezentująca tablicę routingu
class RoutingTable {
    vector<Route> routes;
public:
    void addRoute(const Route& r) {
        routes.push_back(r);
    }

    void removeRoute(const IPAddress& network) {
        auto it = remove_if(routes.begin(), routes.end(),
            [&](const Route& r) { return r.getNetwork() == network; });

        if (it != routes.end()) {
            routes.erase(it, routes.end());
            cout << "Trasa została usunięta.\n";
        } else {
            cout << "Nie znaleziono podanej trasy.\n";
        }
    }

    optional<Route> findRoute(const IPAddress& addr) const {
        optional<Route> best;
        for (const auto& r : routes) {
            if (r.matches(addr)) {
                if (!best || r.getNetwork().getPrefix() > best->getNetwork().getPrefix()) {
                    best = r;
                }
            }
        }
        return best;
    }

    void print() const {
        if (routes.empty()) {
            cout << "Tablica routingu jest pusta.\n";
            return;
        }

        vector<Route> sorted = routes;
        sort(sorted.begin(), sorted.end(), [](const Route& a, const Route& b) {
            return a.getMetric() < b.getMetric();
        });

        cout << "Aktualna tablica routingu:\n";
        for (const auto& r : sorted)
            cout << "  " << r.toString() << endl;
    }
};

// ------------------------- Packet -------------------------
// Klasa reprezentująca pakiet
class Packet {
    IPAddress source;
    IPAddress destination;
    string protocol;
public:
    Packet(const IPAddress& src, const IPAddress& dst, const string& proto)
        : source(src), destination(dst), protocol(proto) {}

    const IPAddress& getDestination() const { return destination; }

    string toString() const {
        ostringstream oss;
        oss << "Pakiet od " << source.toString()
            << " do " << destination.toString()
            << " [" << protocol << "]";
        return oss.str();
    }
};

// ------------------------- RouterCLI -------------------------
// Klasa odpowiedzialna za interfejs wiersza poleceń (CLI) dla symulatora routera
class RouterCLI {
    RoutingTable table;
    ofstream log;
public:
    RouterCLI() : log("router.log", ios::app) {}

    void run() {
        string cmd;
        printHelp();

        while (true) {
            cout << "\n> ";
            if (!getline(cin, cmd)) break;

            istringstream ss(cmd);
            string op;
            ss >> op;

            try {
                if (op == "add") handleAdd(ss);
                else if (op == "del") handleDelete(ss);
                else if (op == "show") table.print();
                else if (op == "send") handleSend(ss);
                else if (op == "help") printHelp();
                else if (op == "exit") break;
                else cout << "Nieznane polecenie. Wpisz 'help' aby zobaczyć dostępne komendy.\n";
            } catch (const exception& e) {
                cout << "Błąd: " << e.what() << endl;
            }
        }
    }

private:
    void printHelp() const {
        cout << "=== Symulator Routera IP ===\n";
        cout << "Dostępne polecenia:\n";
        cout << "  add <sieć> <brama> <metryka>  - dodaje trasę (np. add 192.168.1.0/24 192.168.1.1 10)\n";
        cout << "  del <sieć>                    - usuwa trasę (np. del 192.168.1.0/24)\n";
        cout << "  show                          - pokazuje tablicę routingu\n";
        cout << "  send <źródło> <cel> <prot>    - wysyła pakiet (np. send 10.0.0.1 192.168.1.100 ICMP)\n";
        cout << "  help                          - pokazuje tę pomoc\n";
        cout << "  exit                          - kończy program\n";
    }

    void handleAdd(istringstream& ss) {
        string net, gw;
        int m;
        if (!(ss >> net >> gw >> m)) {
            cout << "Użycie: add <sieć> <brama> <metryka>\n";
            return;
        }

        table.addRoute(Route(IPAddress(net), IPAddress(gw), m));
        cout << "Dodano trasę.\n";
        log << "ADD " << net << " przez " << gw << " metryka " << m << "\n";
    }

    void handleDelete(istringstream& ss) {
        string net;
        if (!(ss >> net)) {
            cout << "Użycie: del <sieć>\n";
            return;
        }

        table.removeRoute(IPAddress(net));
        log << "DEL " << net << "\n";
    }

    void handleSend(istringstream& ss) {
        string src, dst, proto;
        if (!(ss >> src >> dst >> proto)) {
            cout << "Użycie: send <źródło> <cel> <protokół>\n";
            return;
        }

        Packet pkt(IPAddress(src), IPAddress(dst), proto);
        cout << pkt.toString() << endl;

        auto r = table.findRoute(pkt.getDestination());
        if (r) {
            cout << "Przekazuję pakiet przez bramę: " << r->getGateway().toString() << endl;
            log << "FWD " << pkt.toString() << " przez " << r->getGateway().toString() << "\n";
        } else {
            cout << "Pakiet został odrzucony (brak odpowiedniej trasy).\n";
            log << "DROP " << pkt.toString() << "\n";
        }
    }
};



int main() {
    RouterCLI cli;
    cli.run();
    return 0;
}
