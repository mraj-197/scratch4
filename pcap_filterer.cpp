#include <pcap.h>
#include <iostream>
#include <cstdlib>
#include <ctime>

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap> <output.pcap>\n";
        return 1;
    }

    const char* input_file = argv[1];
    const char* output_file = argv[2];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* input_handle = pcap_open_offline(input_file, errbuf);
    if (!input_handle) {
        std::cerr << "Failed to open input file: " << errbuf << '\n';
        return 1;
    }

    // Use same link-layer header type for output
    int linktype = pcap_datalink(input_handle);
    pcap_dumper_t* output_dumper = nullptr;

    // Output file will be created with the same snapshot length and link-layer type
    pcap_t* dummy_handle = pcap_open_dead(linktype, 65535);
    output_dumper = pcap_dump_open(dummy_handle, output_file);
    if (!output_dumper) {
        std::cerr << "Failed to open output file for writing: " << pcap_geterr(dummy_handle) << '\n';
        pcap_close(input_handle);
        return 1;
    }

    srand(static_cast<unsigned int>(time(nullptr)));

    const int max_skip = 5;
    int packets_to_skip = 0;

    struct pcap_pkthdr* header;
    const u_char* data;
    int status;

    while ((status = pcap_next_ex(input_handle, &header, &data)) >= 0) {
        if (packets_to_skip > 0) {
            packets_to_skip--;
            continue;
        }

        // Randomly decide to skip N packets after this one
        bool skip_now = rand() % 5 == 0; // 20% chance to start skipping
        if (skip_now) {
            packets_to_skip = rand() % (max_skip + 1); // skip 0 to max_skip packets
        }

        // Dump current packet
        pcap_dump(reinterpret_cast<u_char*>(output_dumper), header, data);
    }

    if (status == -1) {
        std::cerr << "Error reading packets: " << pcap_geterr(input_handle) << '\n';
    }

    pcap_dump_close(output_dumper);
    pcap_close(input_handle);
    pcap_close(dummy_handle);

    std::cout << "Filtered packets written to: " << output_file << '\n';
    return 0;
}
