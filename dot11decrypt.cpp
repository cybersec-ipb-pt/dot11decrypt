/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * Author: Matias Fontanini <matias.fontanini@gmail.com>
 *
 * This small application decrypts WEP/WPA2(AES and TKIP) traffic on
 * the fly and writes the result into a tap interface.
 *
 */

// libtins
#include <tins/tins.h>
// linux/POSIX stuff
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
// STL
#include <iostream>
#include <atomic>
#include <algorithm>
#include <tuple>
#include <string>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <memory>

using namespace Tins;

using std::atomic;
using std::lock_guard;
using std::mutex;
using std::unique_ptr;
using std::unique_lock;
using std::condition_variable;
using std::move;
using std::memset;
using std::bind;
using std::cout;
using std::endl;
using std::runtime_error;
using std::invalid_argument;
using std::exception;
using std::thread;
using std::swap;
using std::tuple;
using std::make_tuple;
using std::string;
using std::queue;
using std::get;
using std::vector;

// our running flag
atomic<bool> running;

// PCAP file
PacketWriter *packetWriter;

auto DUMP_FILE_NAME = "dump.pcap";

// packet_buffer - buffers packets, decrypts them and flushes them into
// the interface using an auxiliary thread.

class packet_buffer {
public:
    typedef unique_ptr<PDU> unique_pdu;

    packet_buffer(Crypto::WPA2Decrypter wpa2d,
                  Crypto::WEPDecrypter wepd)
            : wpa2_decrypter_(move(wpa2d)), wep_decrypter_(move(wepd)) {
        // Requires libtins 3.4
#ifdef TINS_HAVE_WPA2_CALLBACKS
        using namespace std::placeholders;
        wpa2_decrypter_.ap_found_callback(bind(&packet_buffer::on_ap_found, this, _1, _2));
        wpa2_decrypter_.handshake_captured_callback(bind(&packet_buffer::on_handshake_captured,
                                                         this, _1, _2, _3));
#endif // TINS_HAVE_WPA2_CALLBACKS
    }

    packet_buffer(const packet_buffer &) = delete;

    packet_buffer &operator=(const packet_buffer &) = delete;

    ~packet_buffer() {
        thread_.join();
    }

    void add_packet(unique_pdu pkt) {
        lock_guard<mutex> _(mtx_);
        packet_queue_.push(move(pkt));
        cond_.notify_one();
    }

    void stop_running() {
        lock_guard<mutex> _(mtx_);
        cond_.notify_one();
    }

    void run() {
        thread_ = thread(&packet_buffer::thread_proc, this);
    }

private:
    typedef HWAddress<6> address_type;

    void on_ap_found(const string &ssid, const address_type &bssid) {
        cout << "AP found: " << ssid << ": " << bssid << endl;
    }

    void on_handshake_captured(const string &ssid, const address_type &bssid,
                               const address_type &client_hw) {
        cout << "Captured handshake for " << ssid << " (" << bssid << "): " << client_hw << endl;
    }

    template<typename Decrypter>
    bool try_decrypt(Decrypter &decrypter, PDU &pdu) {

        // try to decrypt the packet
        bool success = decrypter.decrypt(pdu);

        // if the decryption failed the packet is left intact
        packetWriter->write(pdu);

        return success;
    }

    void thread_proc() {
        while (running) {
            unique_pdu pkt;
            // critical section
            {
                unique_lock<mutex> lock(mtx_);
                if (!running) {
                    return;
                }
                if (packet_queue_.empty()) {
                    cond_.wait(lock);
                    // if it's still empty, then we're done
                    if (packet_queue_.empty()) {
                        return;
                    }
                }
                pkt = move(packet_queue_.front());
                packet_queue_.pop();
            }
            // non-critical section
            if (!try_decrypt(wpa2_decrypter_, *pkt.get())) {
                try_decrypt(wep_decrypter_, *pkt.get());
            }
        }
    }

    thread thread_;
    mutex mtx_;
    condition_variable cond_;
    queue<unique_pdu> packet_queue_;
    Crypto::WPA2Decrypter wpa2_decrypter_;
    Crypto::WEPDecrypter wep_decrypter_;
};


// traffic_decrypter - decrypts the traffic and forwards it into a
// bufferer

class traffic_decrypter {
public:
    traffic_decrypter(Crypto::WPA2Decrypter wpa2d,
                      Crypto::WEPDecrypter wepd)
            : bufferer_(move(wpa2d), move(wepd)) {

    }

    void decrypt_traffic(Sniffer &sniffer) {
        using std::placeholders::_1;

        bufferer_.run();
        sniffer.sniff_loop(bind(&traffic_decrypter::callback, this, _1));
        bufferer_.stop_running();
    }

private:
    bool callback(PDU &pdu) {
        if (pdu.find_pdu<Dot11>() == nullptr && pdu.find_pdu<RadioTap>() == nullptr) {
            throw runtime_error("Expected an 802.11 interface in monitor mode");
        }
        bufferer_.add_packet(packet_buffer::unique_pdu(pdu.clone()));
        return running;
    }

    packet_buffer bufferer_;
};


// sig_handler - SIGINT handler, so we can release resources appropriately
void sig_handler(int) {
    if (running) {
        cout << "Stopping the sniffer...\n";
        running = false;
    }
}


typedef tuple<Crypto::WPA2Decrypter, Crypto::WEPDecrypter> decrypter_tuple;

// Creates a traffic_decrypter and puts it to work
void decrypt_traffic(const string &iface, decrypter_tuple tup, vector<string> ap_filter) {

    string mac_filter = "";

    for (const auto &i: ap_filter) {
        mac_filter += "wlan addr3 " + i + " or wlan addr4 " + i +
                      " or wlan addr1 " + i + " or wlan addr2 " + i;

        if (i != ap_filter.back())
            mac_filter += " or ";
    }

    SnifferConfiguration config;
    config.set_promisc_mode(false);
    config.set_filter(mac_filter);
    config.set_snap_len(0);

    Sniffer sniffer(iface, config);

    traffic_decrypter decrypter(
            move(get<0>(tup)),
            move(get<1>(tup))
    );
    decrypter.decrypt_traffic(sniffer);
}

// parses the arguments and returns a tuple (WPA2Decrypter, WEPDectyper)
// throws if arguments are invalid
decrypter_tuple parse_args(const vector<string> &args) {
    decrypter_tuple tup;
    for (const auto &i: args) {
        if (i.find("wpa:") == 0) {
            auto pos = i.find(':', 4);
            if (pos != string::npos) {
                get<0>(tup).add_ap_data(
                        i.substr(pos + 1), // psk
                        i.substr(4, pos - 4) // ssid
                );
            } else {
                throw invalid_argument("Invalid decryption data");
            }
        } else if (i.find("wep:") == 0) {
            const auto sz = string("00:00:00:00:00:00").size();
            if (sz + 4 >= i.size()) {
                throw invalid_argument("Invalid decryption data");
            }
            get<1>(tup).add_password(
                    i.substr(5, sz), // bssid
                    i.substr(5 + sz) // passphrase
            );
        } else {
            throw invalid_argument("Expected decription data.");
        }
    }
    return tup;
}

void print_usage(const char *arg0) {
    cout << "Usage: " << arg0 << " <interface> DECRYPTION_DATA FILTER [...]\n\n";
    cout << "Where DECRYPTION_DATA can be: \n";
    cout << "\twpa:SSID:PSK - to specify WPA2(AES or TKIP) decryption data.\n";
    cout << "\twep:BSSID:KEY - to specify WEP decryption data.\n";
    cout << "Where FILTER are the mac addresses of the AP (if not supplyed the whole channel will be captured)\n\n";
    cout << "Examples:\n";
    cout << "\t" << arg0 << " wlan0 wpa:MyAccessPoint:some_password\n";
    cout << "\t" << arg0 << " wlan0 wpa:MyAccessPoint:some_password 00:0f:24:7a:c7:90 12:0f:24:7a:c7:90\n";
    cout << "\t" << arg0 << " mon0 wep:00:01:02:03:04:05:blahbleehh\n";
    exit(1);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(*argv);
    }
    try {

        packetWriter = new PacketWriter(DUMP_FILE_NAME, DataLinkType<RadioTap>());

        auto decrypters = parse_args(vector<string>(argv + 2, argv + 3));
        signal(SIGINT, sig_handler);
        running = true;
        cout << "\n";

        vector<string> ap_filter{};
        for (int i = 3; i < argc; i++) {
            ap_filter.insert(ap_filter.end(), argv[i]);
        }

        decrypt_traffic(argv[1], move(decrypters), ap_filter);
        cout << "Done\n";
    }
    catch (invalid_argument &ex) {
        cout << "[-] " << ex.what() << endl;
        print_usage(*argv);
    }
    catch (exception &ex) {
        cout << "[-] " << ex.what() << endl;
    }
}
