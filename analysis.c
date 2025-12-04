#define _DEFAULT_SOURCE
#include "analysis.h"
#include "dispatch.h"

#include <pcap.h>
#include <pthread.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>


// Mutex lock for updating report values (the values are global so need locking)
pthread_mutex_t report_mutex = PTHREAD_MUTEX_INITIALIZER;

int syn_count = 0;
int arp_response_count = 0;
int blacklist_google = 0;
int blacklist_facebook = 0;

unsigned int* arr_ptr = NULL;
int arr_size = 0;

// Method to insert IP into dynamic array if unique
void insert_new_ip(unsigned int source_ip){
    int i = 0;
    bool duplicate = false;

    // Search for the IP address in the queue in case its not unique
    while (!duplicate && i < arr_size){
      if (arr_ptr[i] == source_ip){
        duplicate = true;
      }
      i++;
    }

    // If unique...
    if (!duplicate){
      unsigned int *temp = arr_ptr;

      // Increment the size of the array (could use a more optimised array resizing strategy, but this is simple)
      arr_ptr = realloc(arr_ptr, (arr_size + 1) * sizeof(unsigned int));
      
      if (!arr_ptr){
        // If allocation fails, revert the queue back to what it was before
        printf("Memory Re-allocation failed");
        arr_ptr = temp;
      } else{
        arr_ptr[arr_size] = source_ip;
        arr_size++;
      }
    }
}


void analyse(struct pcap_pkthdr *header,
             const unsigned char *packet,
             int verbose) {
    
    // Extracting the ethernet header (start of the packet) and its type from the packet pointer
    struct ether_header *eth_header = (struct ether_header *) packet;
    unsigned short ethernet_type = ntohs(eth_header->ether_type);

    if (ethernet_type == ETHERTYPE_ARP){
      // Check if the ARP is request or response
      const unsigned char *eth_start = packet + ETH_HLEN;
      struct ether_arp *arp_header = (struct ether_arp *) eth_start;

      // Detection of an ARP response
      if(ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY){
        pthread_mutex_lock(&report_mutex);
        arp_response_count++;
        pthread_mutex_unlock(&report_mutex);
      }
      
    }else if(ethernet_type == ETHERTYPE_IP){
      // Extracting the ip header by "skipping" over ethernet header
      const unsigned char *ip_start = packet + ETH_HLEN;
      struct ip *ip_header = (struct ip *) ip_start;
      const unsigned short ip_header_length = (ip_header->ip_hl) * 4;
      unsigned short ip_type = ip_header->ip_p;
      
      // Checking for TCP
      if (ip_type == IPPROTO_TCP){
        // Extracting the tcp header by skipping the ip header
        const unsigned char *tcp_start = (unsigned char *)ip_header + (ip_header_length);
        struct tcphdr *tcp_header = (struct tcphdr *) tcp_start;
        int port = ntohs(tcp_header->th_dport);

        if (port == 80){
          // Check payload is one of the blacklisted url's
          const short tcp_header_length = tcp_header->th_off * 4; // Multiply by 4 since data offset is number of chunks of 4 bytes
          const unsigned char *payload = (unsigned char *)tcp_header + tcp_header_length; // Unsigned char used so addition is right
          const short total_headers_length = ETH_HLEN + ip_header_length + tcp_header_length;
          const short payload_length = header->len - total_headers_length;
          
          if (payload_length > 0) { // Precautionary check
              int payload_best_len = payload_length < 2048 ? payload_length : 2048; // Makes sure payload is cut off at a suitable point to include HTTP headers
              char buffer[2049];

              // Copy payload to the buffer so we can add null character to enable use of strstr with termination
              memcpy(buffer, payload, payload_best_len);

              buffer[payload_best_len] = '\0'; // Makes sure to end the search if following domains not found

              // Search the buffer for the domains
              if (strstr(buffer, "Host: www.google.co.uk")) {
                  pthread_mutex_lock(&report_mutex);
                  printf("==============================\n Blacklisted URL violation detected\n Source IP address: %s\n Destination IP address: %s (google)\n ==============================\n", inet_ntoa(ip_header->ip_src),inet_ntoa(ip_header->ip_dst));
                  blacklist_google++;
                  pthread_mutex_unlock(&report_mutex);
              }
              else if (strstr(buffer, "Host: www.facebook.com")) {
                pthread_mutex_lock(&report_mutex);
                printf("==============================\n Blacklisted URL violation detected\n Source IP address: %s\n Destination IP address: %s (facebook)\n ==============================\n", inet_ntoa(ip_header->ip_src),inet_ntoa(ip_header->ip_dst));
                blacklist_facebook++;
                pthread_mutex_unlock(&report_mutex);
              }
          }
        }
        
        // Checking for SYN packets
        if (tcp_header->th_flags & TH_SYN && !(tcp_header->th_flags & TH_ACK)){ // Bitwise operation for specific SYN bit and make sure ACK is 0
          // Insert the source IP if unique to the dynamic array and increment count
          pthread_mutex_lock(&report_mutex);
          insert_new_ip(ip_header->ip_src.s_addr);
          syn_count++;
          pthread_mutex_unlock(&report_mutex);
        }

      }
    }
}

// Function called when SIGNINT signal received to exit program
void signal_handle(){
  // Finish all thread work
  terminate();

  // Print report
  printf("\nIntrusion Detection Report:\n");
  printf("%d SYN  packets detected from %d different IPs (syn attack)\n",syn_count, arr_size);
  printf("%d ARP responses (cache poisoning)\n",arp_response_count);
  printf("%d URL Blacklist violations (%d google and %d facebook)\n", (blacklist_google + blacklist_facebook), blacklist_google, blacklist_facebook);
  
  // Free the array of unique IP's
  if (arr_ptr) free(arr_ptr);

  exit(0);
}
