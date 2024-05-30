#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#define SNAP_LEN 1518  // Max bytes per packet
#define SIZE_ETHERNET 14
#define WLAN_RADIO_HDR_LEN 8
void extract_htcap(const u_char *support_datarate);
int frame=0;
int tag_len;
// Radiotap header
struct radiotap_header {
    u_int8_t it_version;
    u_int8_t it_pad;
    u_int16_t it_len;
    u_int32_t it_present;
};
struct radiotap_header *ptr;

// Define the IEEE 802.11 beacon frame structure (simplified)
struct beacon_frame {
    uint8_t type_subtype;
    uint8_t flags;
    uint16_t duration;
    uint8_t receiver_address[6];
    uint8_t destination_address[6];
    uint8_t transmitter_address[6];
    uint8_t source_address[6];
    uint8_t fragment_number:4;
    uint8_t sequence_number:8;
    // Followed by fixed parameters and tagged parameters...
};

void  extract_htcap(const u_char *support_datarate)
{
    
      printf("entered\n");
     //uint16_t ht_cap;
     //printf("%x\n",support_datarate);
     const u_char *i,*j;
     i=support_datarate;
     //printf("%x\n",i);
     //printf("%x\n",(i+100));
     j = i+100;
     for(i;i<j;i++)
     {
      
         if(*i == 0x2d)
         {
             const u_char *lsb = (i+2) ;
             const u_char *msb = (i+3) ;
             printf("capacity 1 is %x\n",*lsb);
             printf("capacity 2 is %x\n",*msb);
             
             if(*lsb & 0x0002 == 1 ) // the channel width supports to both 20MHz and 40M Hz
             {
                printf("the channel width supports to both 20MHz and 40MHz\n");
             }
             else
             {
                printf("the channel width supports to 20Mhz only\n");
             }
         }
      
     }

        
     

}


u_char* extract_datarates(const u_char *tagged_params)
{
  const u_char *support_datarate = tagged_params + *(tagged_params + 1) + 2;
  tag_len = *(support_datarate+1);
  int data[tag_len];
  uint16_t ele_id = 0x32;
  int i=0;
  for(i=0;i<tag_len;i++)
  {
       data[i]=(int)*(support_datarate+2+i);
  }
 
  if(tag_len == 5)
  {
      printf("access point uses the 802.11b standard\n\n");
      printf("ACCESS POINT supported data rates is  1  2 5.5 11 (Mbit/sec)\n");
  }
  else if(tag_len>=8)
  {
       printf("accsee point uses the 802.11g\n");
       printf("ACCESS POINT supported data rates is  1  2 5.5 11 12 18 24 36 48 54 (Mbit/sec)\n");
  }
  
  printf("Supported Rates Information Element:\n");
  printf("Element ID: 0x%02X\n",ele_id);
  printf("tag length is %d\n",tag_len);
  
  
  // Iterate over supported rates data and print each rate
    for (int i = 0; i < tag_len; i++) {
        // Extract rate from data and convert to Mbps
        uint8_t rate = data[i] & 0x7F; // Mask out the MSB, which indicates basic rate
        float rate_mbps = (float)rate / 2.0;

        // Check if the rate is a basic rate
        if (data[i] & 0x80) {
            printf("  Basic Rate: %.1f Mbps\n", rate_mbps);
        } else {
            printf("  Supported Rate: %.1f Mbps\n", rate_mbps);
        }
    }
  
 
  printf("\n");
  return support_datarate;
  
  
}

// Define a simple function to print MAC addresses in a readable format
void print_mac_address(uint8_t *addr) {
    for (int i = 0; i < 5; ++i) {
        printf("%02x:", addr[i]);
    }
    printf("%02x ", addr[5]);
    //printf("\n");
}

void print_da_address(const uint8_t *addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    //printf("\n");
}

void print_sa_address(const uint8_t *addr) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x ", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
    //printf("\n");
}

void extract_ssid(const u_char *tagged_params, size_t length) {
    size_t i = 0;
    while (i < length) {
        uint8_t tag_type = tagged_params[i];
        uint8_t tag_len = tagged_params[i + 1];
        if (tag_type == 0) { // SSID tag type
            printf("Beacon(");
            for (int j = 0; j < tag_len; ++j) {
                char ssid_char = tagged_params[i + 2 + j];
                printf("%c", ssid_char);
            }
            break;
        }
        if(tag_type == 2) { //supported rates
        
        }
        i += 2 + tag_len; // Move to the next tag
    }
    printf(")");
    
}
void extract_channel(const u_char *packet)
{
      uint8_t freq1 = *(packet + 26);
      uint8_t freq2= *(packet+27);
      int i;
      printf("%x %x\n",freq1,freq2);
      
      uint16_t freq = freq2;
      for(i=0;i<8;i++)
      {
         freq = freq << 1;
      }
      freq = freq | freq1;
      printf("Channel Freq %d Hz\n",freq);
      if (freq >= 2412 && freq <= 2472) 
      {
        // 2.4 GHz band (Channels 1-13)
        printf("Channel %d\n",(freq - 2407) / 5);
      }
      else if (freq == 2484) 
      {
        // 2.4 GHz band (Channel 14)
        printf("Channel 14\n");
      } 
      else if (freq >= 5180 && freq <= 5825) 
      {
        // 5 GHz band
        printf("Channel %d\n",(freq - 5000) / 5);
      }
      else 
      {
        // Unknown frequency
        printf("unknown frequency\n");
      }
      
}


int determine_offset(const uint8_t *packet) {
    // Check if the packet starts with a radiotap header
    // A radiotap header typically starts with a version byte (0x00) followed by a length field
    // The length field indicates the total length of the radiotap header
    if (packet[0] == 0x00 && packet[1] > 0) {
        // The length of the radiotap header is stored in the second byte
        int radiotap_length = packet[1];

        // The IEEE 802.11 header usually starts after the radiotap header
        // Add the length of the radiotap header to get the offset
        int offset = radiotap_length;

        return offset;
    } else {
        // If there's no radiotap header, assume the IEEE 802.11 header starts at the beginning of the packet
        return 0;
    }
}

// Function to parse and print packet
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct tm *ltime;
    char timestr[16];
    int n;
    time_t local_tv_sec;
    ++frame;

    local_tv_sec = header->ts.tv_sec;
    ltime=localtime(&local_tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    printf("FRAME NUMBER:%d\n",frame);
    printf("\nPACKET INFO:\n");
    printf("Time stamp : %s.%06ld\n", timestr, header->ts.tv_usec);

    // Assuming the packet starts with a radiotap header  TYPECASTING
    struct radiotap_header *rth = (struct radiotap_header *)(packet);

    // Skipping the radiotap header for simplicity; you'd parse specific fields as needed
    int header_len = rth->it_len;

    // Now, get to the beacon frame
    struct beacon_frame *bf = (struct beacon_frame *)(packet + header_len);  //SKIP

    // Extract and print the BSSID (transmitter address for beacon frames)
    printf("BSSID:");
    print_mac_address(bf->transmitter_address);

    // Pointer to the start of the IEEE 802.11 header, right after the Radiotap header
    const uint8_t *ieee80211_header = packet + header_len;

    // Destination Address is the first address field in the 802.11 header for management frames
    const uint8_t *da = ieee80211_header + 4; // Skipping Frame Control (2 bytes) and Duration (2 bytes)

    // Print the Destination Address
    printf("DA:");
    print_da_address(da);

    // Assuming the IEEE 802.11 header directly follows the Radiotap header
    ieee80211_header = packet + header_len;

    // In a typical management frame like a beacon, DA, SA, and BSSID can essentially hold the same value.
    // For educational purposes, we're treating the third MAC address as the Source Address (SA) here.
    const uint8_t *sa = ieee80211_header + 4 + 6; // Skipping Frame Control (2 bytes), Duration (2 bytes), and DA (6 bytes)

    // Print the Source Address
    printf("SA:");
    print_sa_address(sa);
    //printf("\n");

    bf = (struct beacon_frame *)(packet + header_len + 24);
    
    // Tagged parameters start after the fixed parameters of the beacon frame
    // Fixed parameters are 12 bytes, but this could vary, adjust accordingly
    const u_char *tagged_params = packet + header_len + 24 + 12;
    size_t params_length = header->caplen - (header_len + 24 + 12);
    printf("\ncap_length %d\n",header->caplen);
    printf("length %d\n",header->len);
    
   // printf("address tagged params is %x\n",tagged_params);
    
    //uint16_t *support_datarate = (int*)(tagged_params) + (int)(*(tagged_params+1));
    
    //printf("supported data rate is %x\n",support_datarate);
    //printf("address of next is %d\n",(int)(*(tagged_params+1)));
    //printf("tagged params %d\n",(int)(*tagged_params));


    // Extract and print the SSID
    extract_ssid(tagged_params, params_length);

   
    // Print the length of the packet

    printf("Packet length: %d bytes\n", header->len);
    
    printf("SSID PARAMETER SET IS : %x\n",tagged_params[0]); 
    
   
    
    u_char *support_datarate = extract_datarates(tagged_params);
    printf("supported data rates captured\n");
    extract_htcap(support_datarate);
    extract_channel(packet);
    
   
    
    // Loop through each byte in the packet and print its hexadecimal value
	for (int i = 0; i < header->len; ++i) {
		printf("%02x ", packet[i]); // Print the hexadecimal value of each byte
		if ((i + 1) % 8 == 0) {
			printf(" "); // Add an extra space after every 8 bytes for readability
		}
		if ((i + 1) % 16 == 0) {
			// Print ASCII representation of the bytes after every 16 bytes
			printf("   ");
			for (int j = i - 15; j <= i; ++j) {
				// Print the ASCII character if it's printable, otherwise print a dot '.'
				printf("%c", (packet[j] >= 32 && packet[j] <= 126) ? packet[j] : '.');
			}
			printf("\n"); // Newline after every 16 bytes
		}
	}
	// Print the remaining ASCII characters if the total bytes are not a multiple of 16
	if (header->len % 16 != 0) {
		int remainder = 16 - (header->len % 16);
		for (int i = 0; i < remainder; ++i) {
			printf("   "); // Spaces for alignment
		}
		for (int i = header->len - (header->len % 16); i < header->len; ++i) {
			printf("%c", (packet[i] >= 32 && packet[i] <= 126) ? packet[i] : '.');
		}
	}
	printf("\n\n"); // Two newlines after printing the packet contents
    printf("\n");

    
    
    
}

int main(int argc, char *argv[]) {
    char *dev = NULL;  // Capture device name
    char errbuf[PCAP_ERRBUF_SIZE];  // Error buffer
    pcap_t *handle;  // Packet capture handle

    char filter_exp[] = "type mgt and (subtype beacon or subtype probe-resp or subtype probe-req)";  // Filter expression
    struct bpf_program fp;  // Compiled filter
    bpf_u_int32 mask;  // Subnet mask
    bpf_u_int32 net;  // IP

    // Open capture device
    handle = pcap_open_live("wlp0s20f3", SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }

    // Compile the filter expression
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Apply the compiled filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // Start the capture
    pcap_loop(handle, -1, got_packet, NULL);

    // Cleanup
    pcap_freecode(&fp);
    pcap_close(handle);

    printf("\nCapture complete.\n");
    return 0;
}









 //int ieee80211_header_offset = 0/*determine_offset(packet)*//* offset value here */; // This needs to be determined dynamically or set based on your environment
 /*
    const uint8_t *frame_body = packet + ieee80211_header_offset;

    // Assuming we're directly at the frame body of a Beacon frame...
    // Skip fixed parameters of Beacon frame to reach the tagged parameters
    int fixed_parameters_length = 12; // Timestamp (8 bytes) + Beacon Interval (2 bytes) + Capability Info (2 bytes)
    tagged_params = frame_body + fixed_parameters_length;
    int tagged_params_length = header->caplen - ieee80211_header_offset - fixed_parameters_length;

    // Parse tagged parameters for Supported Rates (ID 1), Extended Supported Rates (ID 50), and DS Parameter Set (ID 3)
    int index = 0;
    while (index < tagged_params_length) {
        uint8_t id = tagged_params[index];
        uint8_t len = tagged_params[index + 1];
        const uint8_t *data = &tagged_params[index + 2];

        switch (id) {
            case 1: // Supported Rates
                printf(" Supported Rates:");
                print_supported_rates(data, len);
                break;
            case 3: // DS Parameter Set (Channel)
                printf(" CH: %d, ", data[0]);
                break;
            case 50: // Extended Supported Rates
                printf(" Extended Supported Rates:");
                print_supported_rates(data, len);
                break;
        }
        index += len + 2; // Move to the next tag
    }

    // Extracting the Capability Info directly for Privacy bit
    const uint16_t *capability_info = (const uint16_t *)(frame_body + 10); // Offset 10 within the beacon frame body
    printf(" PRIVACY: %s\n", (*capability_info & 0x0010) ? "Yes" : "No");
    
    
 */

