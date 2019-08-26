#define TINS_STATIC
#define WPCAP

#include <tins/tins.h>
#include <iostream>
#include <vector>
#include <math.h>
#include <string>
#include <map>
#include <deque>
#include <fstream>

using namespace Tins;
using namespace std;
using namespace std::chrono;

size_t counter(0);
int packet_limit;
int packet_interval;
double min_pps = 0.1;
int min_streak = 25;
Timestamp first;
long double lastTime;
map<int, string> portToProtocol = {
	{5060, "SIP"},
	{5061, "SIP"},
	{53, "DNS"},
	{19, "CharGen"},
	{1434, "MSSQL"},
	{3544, "Teredo"},
	{137, "NetBios"},
	{161, "SNMP"},
	{123, "NTP"},
	{1900, "SSDP"},
	{17, "QOTD"},
	{27960, "Quake 3"},
	{27015, "Steam"}
};

class finishedAttack {
private:
	double pps;
	int port;
	string protocol;
	long double start;
	long double end;
	int packettotal;
public:
	IPv4Address src;
	finishedAttack(IPv4Address s, double p, int por, string prot, long double star, long double en, int pack) {
		src = s;
		pps = p;
		port = por;
		protocol = prot;
		start = star;
		end = en;
		packettotal = pack;
	}
	void print() {
		cout << "Ip: " << src << endl;
		cout << "Total Packets: " << packettotal << endl;
		cout << "Packets/Sec: " << pps << endl;
		cout << "Start Time: " << start << endl;
		cout << "End Time: " << end << endl;
		cout << "Protocol Type: " << protocol << endl;
		cout << "Port #: " << port << endl;
		cout << endl;
	}
};

vector<finishedAttack> attacks;

class active_ip {
private:
	int streak = 1;
public:
	IPv4Address src;
	double pps;
	int port;
	string protocol;
	long double start;
	deque<long double> tempTime;
	int packettotal = 1;
	bool attack = false;
	active_ip(IPv4Address s, long double time, int p) {
		src = s;
		tempTime.push_back(time);
		port = p;
		if (portToProtocol.find(p) != portToProtocol.end()) {
			protocol = portToProtocol[p];
		}
		else {
			protocol = "unknown";
		}
	}
	bool check(IPv4Address s, long double time, int p) {
		if ((s == src) && (port == p)) {
			packettotal++;
			double interval;
			if (streak < min_streak) {
				streak++;
				interval = time - tempTime.front();
			}
			else {
				interval = time - tempTime[1];
			}
			
			double newPps = streak / interval;
			if ((newPps >= min_pps) && (streak == min_streak)) {
				if (attack == false) {
					attack = true;
					start = tempTime.front();
				}
			}
			else if (attack == true) {
				attack = false;
				attacks.push_back(finishedAttack(src, pps, port, protocol, start, tempTime.back(), packettotal));
				packettotal = 0;
			}
			if (streak == min_streak) {
				tempTime.pop_front();
			}
			tempTime.push_back(time);
			pps = packettotal / (time-start);
			return true;
		}
		return false;
	}
	void finish() {
		if (attack == true) {
			attacks.push_back(finishedAttack(src, pps, port, protocol, start, tempTime.back(), packettotal));
		}
	}
};

vector<active_ip> ips;

long double getTimeDiff(Timestamp a, Timestamp b) {
	long double seconds = a.seconds() - b.seconds();
	long double ms = a.microseconds()*pow(10,-6) - b.microseconds()*pow(10,-6);
	return seconds + ms;
}

long double getTime(Timestamp timestamp) {
	return getTimeDiff(timestamp, first);
}

void packets(const Packet &packet) {
	const PDU* pdu = packet.pdu();;
	try {
		const IP &ip = (*pdu).rfind_pdu<IP>();
		const UDP &udp = (*pdu).rfind_pdu<UDP>();
	}
	catch (malformed_packet&) { return; }
	catch (pdu_not_found&) { return; };
	const IP &ip = (*pdu).rfind_pdu<IP>();
	const UDP &udp = (*pdu).rfind_pdu<UDP>();
	IPv4Address src = ip.src_addr();
	IPv4Address dst = ip.dst_addr();
	int port = udp.dport();
	long double time = getTime(packet.timestamp());
	lastTime = time;
	bool found = false;
	for (int i = 0; (i < ips.size()) && (!found); i++) {
		found = ips[i].check(src, time, port);
	}
	if (!found) {
		ips.push_back(active_ip(src, time, port));
	}
}

bool init(const Packet packet) {
	first = packet.timestamp();
	return false;
}

int main() {
	cout << "How many packets should be read through?" << endl;
	cin >> packet_limit;
	cout << "In what intervals?" << endl;
	cin >> packet_interval;
	cout << "What is the minimum packets/sec over a number of packets required to be considered an amplification attack?" << endl;
	cin >> min_pps;
	cout << "How many packets must maintain this amount?" << endl;
	cin >> min_streak;
	cout << fixed;
	FileSniffer sniffer1("pcap.pcap");
	Packet packet = sniffer1.next_packet();
	init(packet);

	SnifferConfiguration config;
	config.set_filter("udp");
	FileSniffer sniffer2("pcap.pcap", config);
	cout << endl;
	ofstream myfile;
	myfile.open("ips.txt");
	while (packet_limit > 0) {
		if (packet_limit <= packet_interval) {
			packet_interval = packet_limit;
		}
		for (int i = 0; i < packet_interval; ++i) {
			Packet pkt = sniffer2.next_packet();
			if (!pkt) {
				break;
			}
			packets(pkt);
		}
		packet_limit -= packet_interval;
		for (int j = 0; j < ips.size(); j++) {
			ips[j].finish();
		}
		for (int j = 0; j < attacks.size(); j++) {
			attacks[j].print();
			myfile << attacks[j].src << "\n";
		}
		ips.clear();
		attacks.clear();
		cout << "------------------------------------------------------" << endl;
	}
	myfile.close();
}