/*
 * snoop �ե�������ɤ�ǡ�ɽ���ʤ���¾�ˤ���
 * �ץ���ࡣ 
 * gcc snoopdiag.c -o snoopdiag -lnsl
*/
#include 	<errno.h>
#include	<unistd.h>
#include 	<stdlib.h>
#include	<sys/stat.h>
#include 	<sys/mman.h>
#include 	<strings.h> 
#include 	<fcntl.h>
#include        <netinet/in.h>
#include        <sys/types.h>
#include        <sys/socket.h>
#include        <fcntl.h>
#include        <stdio.h>
#include        <sys/signal.h>
#include        <string.h>
#include        <net/if.h>
#include        <netinet/if_ether.h>
#include        <netinet/in_systm.h>

#define SACK
#define DL_ETHER          4         /* Ethernet */
#define	SNOOP_V2          2
#define ETHERTYPE_IP      0x0800    /* IP protocol */
#define ETHERTYPE_ARP     0x0806    /* Addr. resolution protocol */
#define ETHERTYPE_REVARP  0x8035    /* Reverse ARP */
#define debug 0

#define LIST  0x1	     /* connection list output */
#define VIEW  0x1<<1	     /* view output */
#define DIAG  0x1<<2	     /* packet view with statistics output */
#define BIN   0x1<<3         /* make TCP data files */
#define VIEWUDP   0x1<<4     /* view udp packet pair */

/* Sequence number��Ack number ������ޥ��� */
#define SEQ(stream) ((stream->tcphdr->th_seq[0]<<16) + stream->tcphdr->th_seq[1])
#define ACK(stream) ((stream->tcphdr->th_ack[0]<<16) + stream->tcphdr->th_ack[1])

/* TCP �Υǡ���Ĺ�����롣Fragment Packet �ξ��� IP �Υǡ���Ĺ���֤� */
#define TCPLEN(stream) ( stream->iphdr->ip_off & (8191) ? TCPFRAGMENTLEN(stream) : TCPNONFRAGMENTLEN(stream) )
#define TCPNONFRAGMENTLEN(stream) (stream->iphdr->ip_len - ((stream->iphdr->ip_hl)<<2) - ((stream->tcphdr->th_offset)<<2))
#define TCPFRAGMENTLEN(stream) ((((stream->iphdr->ip_off) & (8191))<<3) + IPLEN(stream) - ((stream->iphdr->ip_hl)<<2))

/* UDP �Υǡ���Ĺ�����롣Fragment Packet �ξ��� IP �Υǡ���Ĺ���֤� */
#define UDPLEN(stream) (stream->iphdr->ip_off & (8191) ? UDPFRAGMENTLEN(stream) : UDPNONFRAGMENTLEN(stream))
#define UDPNONFRAGMENTLEN(stream) (stream->iphdr->ip_len - ((stream->iphdr->ip_hl)<<2) - 8)
#define UDPFRAGMENTLEN(stream) (IPLEN(stream))

/* IP �Υǡ���Ĺ������ */
#define IPLEN(stream)  (stream->iphdr->ip_len - ((stream->iphdr->ip_hl)<<2))

/* Packet �������ˤ�äƽ���ɽ�����֡ʱ�or���ˤ��Ѥ��뤿��Υޥ��� */
#define INDENT(stream)     if(stream->direction) printf("\t\t\t\t\t\t\t\t\t");

/* SYN �⤷���� FIN �ե饰��Ω�äƤ��뤫�ɤ������ǧ���� */
#define SYNFIN(stream)     (( *(stream->tcphdr->th_flags) & (TH_FIN | TH_SYN)) != NULL)


/* Ethernet �إå��� */
struct  etherhdr {
        struct  ether_addr ether_dhost;
        struct  ether_addr ether_shost;
        ushort_t ether_type;
};

/* IP �إå��� */
struct iphdr {
        uchar_t ip_v:4,                 /* version */
                ip_hl:4;                /* header length */
        uchar_t ip_tos;                 /* type of service */
        short   ip_len;                 /* total length */
        ushort_t ip_id;                 /* identification */
        short   ip_off;                 /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
        uchar_t ip_ttl;                 /* time to live */
        uchar_t ip_p;                   /* protocol */
        ushort_t ip_sum;                /* checksum */
       /* ���� IP address �ϰʲ���������ɤ�����������2byte ����Ƥ��ޤ�����*/
       /* struct  in_addr ip_src, ip_dst;   source and dest address �����ΤǤ������� */
	uchar_t ip_src[4];
	uchar_t ip_dst[4];
};

/* TCP Protocol header */
typedef struct tcphdr {
        uint16_t         th_sport;    /* Source port */
        uint16_t         th_dport;    /* Destination port */
        uint16_t        th_seq[2];    /* Sequence number */
        uint16_t        th_ack[2];    /* Acknowledgement number */
        uint8_t         th_offset:4;  /* Offset to the packet data */
        uint8_t         th_reserve:4; /* ͽ��Ѥ� */ 
        uint8_t         th_flags[1];  /* TCP flags */
        uint16_t         th_win;      /* Allocation number */
        uint16_t         th_sum;      /* TCP checksum */
        uint16_t         th_urp;      /* Urgent pointer */
}tcphdr;

typedef struct udphdr {
        uint16_t       uh_sport;               /* source port */
        uint16_t       uh_dport;               /* destination port */
        uint16_t        uh_ulen;               /* udp length */
        uint16_t        uh_sum;                /* udp checksum */
}udphdr;


/* Bit values in 'th_flags' field of the TCP packet header */
#define TH_FIN                  0x01    /* Sender will not send more */
#define TH_SYN                  0x02    /* Synchronize sequence numbers */
#define TH_RST                  0x04    /* Reset the connection */
#define TH_PUSH                 0x08    /* This segment requests a push */
#define TH_ACK                  0x10    /* Acknowledgement field is valid */
#define TH_URG                  0x20    /* Urgent pointer field is valid */


/* ether �� IP �Υإå����碌�� data gram ��¤�� */
struct dgram
{
	struct etherhdr ether;
	struct iphdr    ip;
} ;

/* TCP �� 1 connection ��ι�¤��  */
struct connection_t{
    struct connection_t *conn_head; /* connection list ����Ƭ��*/
    struct connection_t *conn_next; /* connection list �� ���ι�¤�� */
    uchar_t addr0[4];               /* connection �� ��¦�� IP */
    uchar_t addr1[4];               /* connection �� �⤦��¦�� IP */
    uint16_t port0;                 /* connection �� ��¦�� port */
    uint16_t port1;                 /* connection �� �⤦��¦�� port */
    int conn_count;                 /* ���� connection �� Packet �� */
    struct stream_t *stream;        /* ���� connection �κǽ��Packet�� stream_t ��¤�ΤؤΥݥ���*/ 
    struct stream_t *stream_last;   /* ���� connection �κǸ�Packet�� stream_t ��¤�ΤؤΥݥ���*/
    uint32_t snd_nxt[2] ;           /* Diag ���Ѥ� SEQ �οʹԾ��������������Ѱ�*/

}; 
struct connection_t *conn_current, *conn_write, *conn_head;

/* �� connection ��� Packet �� plist �Υ��ɥ쥹���Ǽ������¤�� */
struct stream_t{
	struct stream_t *stream_first;  /* connection �κǽ�� stream_t ��¤�� */ 
	struct stream_t *stream_next;   /* ���� packet �� stream_t ��¤�� */
	struct plist *plist;            /* plist ��¤�ΤؤΥݥ��� */
	struct iphdr *iphdr;            /* IP �إå��Υݥ��� */
        struct tcphdr *tcphdr;          /* TCP �إå��Υݥ��� */
	int    direction;               /* ������ 0 or 1 �� packet ���������������ꤹ�� */ 
};

/* UDP �� port �ڥ� ��ι�¤��  */
struct udp_port_pair_t{
    struct udp_port_pair_t *pair_head; /* udp port pair list ����Ƭ��*/
    struct udp_port_pair_t *pair_next; /* udp port pair list �� ���ι�¤�� */
    uchar_t addr0[4];               /* udp port pair �� ��¦�� IP */
    uchar_t addr1[4];               /* udp port pair �� �⤦��¦�� IP */
    uint16_t port0;                 /* udp port pair �� ��¦�� port */
    uint16_t port1;                 /* udp port pair �� �⤦��¦�� port */
    int pair_count;                 /* ���� udp port pair �� Packet �� */
    struct udp_stream_t *udp_stream;        /* ���� udp port pair �κǽ��Packet�� udp_stream_t ��¤�ΤؤΥݥ���*/ 
    struct udp_stream_t *udp_stream_last;   /* ���� udp port pair �κǸ�Packet�� udp_stream_t ��¤�ΤؤΥݥ���*/
}; 
struct udp_port_pair_t *pair_current, *pair_write, *pair_head;

/* �� udp port pair ��� Packet �� plist �Υ��ɥ쥹���Ǽ������¤�� */
struct udp_stream_t{
	struct udp_stream_t *udp_stream_first;  /* udp port pair �κǽ�� udp_stream_t ��¤�� */ 
	struct udp_stream_t *udp_stream_next;   /* ���� packet �� udp_stream_t ��¤�� */
	struct plist *plist;            /* plist ��¤�ΤؤΥݥ��� */
	struct iphdr *iphdr;            /* IP �إå��Υݥ��� */
        struct udphdr *udphdr;          /* UDP �إå��Υݥ��� */
	int    direction;               /* ������ 0 or 1 �� packet ���������������ꤹ�� */ 
};



/*
 *  snoop �ե������ �ե�����Υإå���
 */
struct snoop_fheader {
	char name[8];
	int version;
	int mactype;
} *fhp; 

/*
 * snoop���γ� packet ��Υإå���
 */
struct snoop_pheader {
	int	pktlen;		/* length of original packet */
	int	caplen;		/* length of packet captured into file */
	int	reclen;		/* length of this packet record */
	int	drops;		/* cumulative drops */
	struct timeval pktime;	/* packet arrival time */
}; 
struct snoop_pheader *php; /* �����Ѥ� snoop packet header ��¤�� */

/*
 * �� packet �����Ѥ�����
 */
struct plist {
	int			packet_number;
        struct plist		*first;        /* plist_head �ؤΥݥ���*/
        struct plist		*nextpkt;      /* ���� plist ��¤�ΤؤΥݥ���*/
	struct snoop_pheader	*php;          /* snoop_pheader ��¤�ΤؤΥݥ���*/
        int             	packet_len;    /* �� packet Ĺ*/
	char			*cap_datap;    /* �� packet �ؤΥݥ���*/
};
struct plist *plist_head;                  /* packet list ��¤�Τ���Ƭ�ؤΥݥ��� */
struct plist *plist_current, *plist_write; /* �����Ѥ� packet list ��¤�� */

int count=0; /* �� packet �� */
int bufflen;
char *buffp; 

int check_ethertype(int );


/*
 * snoop �ե������ open ����
 */
int
sn_open(char *file_name){
	int fd;
	struct stat st;
	char *p;
	
	if ((fd = open(file_name, O_RDONLY, 0664))< 0) {
		perror("open fail");
		return (-1);
	}

	if (fstat(fd, &st) < 0) {
		perror("fstat error");
		return (-1);
	}

	/*
	 * snoop �ե�����������ɤ߹���
	 */
	p = mmap(0, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (p == (char *)-1) {
		perror("mmap error");
		return (-1);
	}
	printf("mmap size(for caputer file): %d\n",st.st_size);        

	buffp = p;

	fhp = (struct snoop_fheader *)buffp;

	/*
	 * snoop �� header �إå������ǧ����
	 */
	if (strcmp((char *)"snoop", (char *)fhp->name) != 0 ||
	    htonl(fhp->version) != SNOOP_V2 ||
	    htonl(fhp->mactype) != DL_ETHER) {
		perror("Not a snoop file!:");
		return (-1);
	}
	printf("File Check OK.\n");

	/*
	 * �ե�����إå���������¥ǡ����� address �ȡ��ǡ���Ĺ������
	 */
	bufflen = st.st_size - sizeof(struct snoop_fheader);
	buffp =  buffp + sizeof(struct snoop_fheader);
	printf("data size: %d\n",bufflen);
	return (0);
}

/*
 * packet ���򥫥���Ƚ�����debug �� 1 �ˤ���� �� packet ��Ĺ���ȡ��в���֤���ϲ�ǽ��
 */
int
sn_count(){
	double  initial_time;
	int data_size;

	php = (struct snoop_pheader *)buffp;
	data_size = bufflen;

	initial_time = php->pktime.tv_sec + (php->pktime.tv_usec  / 1.0e+6);

        printf("Counting numbers of the packets ....");
	while(data_size){ 
		if(debug) printf("Packet Len: %d Time: %f\n",
                                 php->pktlen, (php->pktime.tv_sec + (php->pktime.tv_usec / 1.0e+6) - initial_time));
		data_size -= php->reclen;
		php =  (struct snoop_pheader *)((unsigned int)php + php->reclen);
		count++;
	}
        printf("Done\n");
        

	printf("Number of Packets: %d\n",count);
	return(0);

}

/*
 *  �� packet �ξ���������ꥹ�� plist �س�Ǽ
 */
int 
get_plist(){

	int i;

	printf("malloc size(for packet list): %d\n",sizeof(struct plist)*count);

	if( (plist_head = malloc( (sizeof(struct plist)*count) )) == NULL){
		perror("malloc");
		return(-1);
	}
	php = (struct snoop_pheader *)buffp; 
	plist_current = plist_write = plist_head;

        printf("Listing each packets ...");
	for ( i = 1 ; i < count + 1 ; i++){
		plist_write->packet_number = i;	
		plist_write->first = plist_head;
		plist_write->php = php;
		plist_write->packet_len = php->pktlen; 
		plist_write->cap_datap = (char *)((int)php + sizeof(struct snoop_pheader)); 
		plist_current = plist_write;
		plist_current->nextpkt = ++plist_write;
		php =  (struct snoop_pheader *)((int)php + php->reclen);
	} 
	plist_current->nextpkt = NULL; /* �ꥹ�ȤκǸ�� next pointer �� NULL */
        printf("Done\n");

	return(0);

}

/* ip, tcp �إå������Ƥ��ǧ����connection ��Υ��롼�פ���*/
int check_tcp_header(struct iphdr *iphdr, struct tcphdr *tcphdr, struct plist *plist){
    int i;
    struct connection_t *conn;
    struct stream_t *streams;

    conn = conn_head;

    /* IP address  �� TCP port ���Ȥ߹�碌���顢��¸�� connection list ��̵ͭ��Τ���� */
    while (1){

        /* fragment offset �� 0 �ʳ���fragment���Ƥ���) IP data gram ��Ƚ��*/
        /* �ǽ�� fragment �� TCP �إå����դ��Ƥ���Τǡ��������̲᤹��ɬ�פ�̵��*/
        if (iphdr->ip_off & (8191)){
            
            if (
                (strncmp( (char *) &(iphdr->ip_src[0]), (char *) &(conn->addr0[0]), 4) == 0 &&
                 strncmp( (char *) &(iphdr->ip_dst[0]), (char *) &(conn->addr1[0]), 4) == 0) ||
                (strncmp( (char *) &(iphdr->ip_src[0]), (char *) &(conn->addr1[0]), 4) == 0 &&
                 strncmp( (char *) &(iphdr->ip_dst[0]), (char *) &(conn->addr0[0]), 4) == 0)
                ){

                for (streams = conn->stream ; streams != NULL ; streams = streams->stream_next){
                    /* Ʊ�� IPID ���� packet ��õ��*/
                    if( strncmp((char *)&(iphdr->ip_id), (char *)&(streams->iphdr->ip_id), sizeof(ushort_t)) == 0){
                        /* TCP �إå����� ���Ĥ��ä� fragment �κǽ�� packet �� TCP �إå����Ȥ���*/
                        tcphdr = streams->tcphdr;
                        break;
                    }
                }
            }
        }
        
        
        if ( !(strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(conn->addr0[0]), 4)) && (tcphdr->th_sport == conn->port0) ){
            if  ( !(strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(conn->addr1[0]), 4)) && (tcphdr->th_dport == conn->port1) ){
                streams = malloc(sizeof(struct stream_t)); 
                conn->stream_last->stream_next = streams;
                conn->stream_last = streams;
                streams->stream_next = NULL;
                streams->plist = plist; 
                streams->iphdr = iphdr; 
                streams->tcphdr = tcphdr;
                streams->direction = 0; /* source �� addr0 �� ip �� Ʊ���ʤΤ� direction �� 0 */
                conn->conn_count++;
                return(0);
            }
        } else if ( !(strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(conn->addr1[0]), 4)) && (tcphdr->th_sport == conn->port1) ){
            if  ( !(strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(conn->addr0[0]), 4)) && (tcphdr->th_dport == conn->port0) ){
                streams = malloc(sizeof(struct stream_t)); 
                conn->stream_last->stream_next = streams;
                conn->stream_last = streams;
                streams->stream_next = NULL;
                streams->plist = plist; 
                streams->iphdr = iphdr; 
                streams->tcphdr = tcphdr;
                streams->direction = 1; /* ��ε� */
                conn->conn_count++;
                return(0);

            }
        } 


        if(conn->conn_next == NULL)
            break;
        conn = conn->conn_next;
    }

    /* �ꥹ�Ȥ˴�¸�� connection ��̵���Τǿ����˥ꥹ�Ȥ��ɲ� */
    conn_write = malloc(sizeof(struct connection_t));
    conn_current->conn_next = conn_write;
    for( i = 0 ; i < 4 ; i++){
        conn_write->addr0[i] = iphdr->ip_src[i];
        conn_write->addr1[i] = iphdr->ip_dst[i];
    }
    conn_write->conn_head = conn_head;
    (conn_write->port0) = (tcphdr->th_sport);
    (conn_write->port1) = (tcphdr->th_dport);
    conn_write->conn_next = NULL;
    conn_write->conn_count++;
    conn_write->snd_nxt[0] = 0;
    conn_write->snd_nxt[1] = 0;                
    conn_write->stream = malloc(sizeof(struct stream_t)); 
    conn_write->stream_last = conn_write->stream;
    conn_write->stream->stream_first = conn_write->stream;
    conn_write->stream->stream_next = NULL;
    conn_write->stream->plist = plist; 
    conn_write->stream->iphdr = iphdr; 
    conn_write->stream->tcphdr = tcphdr;
    conn_write->stream->direction = 0; /* �ǽ�� packet ���������Ƥ��������� 0 �Ȥ���*/
    conn_current = conn_write;
			
    return(0);
}

/* ip, udp �إå������Ƥ��ǧ����udp session ��Υ��롼�פ���*/
int check_udp_header(struct iphdr *iphdr, struct udphdr *udphdr, struct plist *plist){
    int i;
    struct udp_port_pair_t *pair;
    struct udp_stream_t *udp_streams;

    pair = pair_head;
    
        
	/* IP address  �� UDP port ���Ȥ߹�碌���顢��¸�� udp port pair list ��̵ͭ��Τ���� */
    while (1){

        /* fragment offset �� 0 �ʳ���fragment���Ƥ���) IP data gram ��Ƚ��*/
        /* �ǽ�� fragment �� UDP �إå����դ��Ƥ���Τǡ��������̲᤹��ɬ�פ�̵��*/
        if (iphdr->ip_off & (8191)){
            
            if (
                (strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(pair->addr0[0]), 4) == 0 &&
                       strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(pair->addr1[0]), 4) == 0) ||
                (strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(pair->addr1[0]), 4) == 0 &&
                       strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(pair->addr0[0]), 4) == 0)
                ){

                for (udp_streams = pair->udp_stream ; udp_streams != NULL ; udp_streams = udp_streams->udp_stream_next){
                        /* Ʊ�� IPID ���� packet ��õ��*/
                    if( strncmp((char *)&(iphdr->ip_id), (char *)&(udp_streams->iphdr->ip_id), sizeof(ushort_t)) == 0){
                            /* UDP �إå����� ���Ĥ��ä� fragment �κǽ�� packet �� UDP �إå����Ȥ���*/
                        udphdr = udp_streams->udphdr;
                        break;
                    }
                }
            }
        }
        
        if ( !(strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(pair->addr0[0]), 4)) && (udphdr->uh_sport == pair->port0) ){
            if  ( !(strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(pair->addr1[0]), 4)) && (udphdr->uh_dport == pair->port1) ){
                udp_streams = malloc(sizeof(struct udp_stream_t)); 
                pair->udp_stream_last->udp_stream_next = udp_streams;
                pair->udp_stream_last = udp_streams;
                udp_streams->udp_stream_next = NULL;
                udp_streams->plist = plist; 
                udp_streams->iphdr = iphdr; 
                udp_streams->udphdr = udphdr;
                udp_streams->direction = 0; /* source �� addr0 �� ip �� Ʊ���ʤΤ� direction �� 0 */
                pair->pair_count++;
                return(0);
            }
        } else if ( !(strncmp( (char *)&(iphdr->ip_src[0]), (char *)&(pair->addr1[0]), 4)) && (udphdr->uh_sport == pair->port1) ){
            if  ( !(strncmp( (char *)&(iphdr->ip_dst[0]), (char *)&(pair->addr0[0]), 4)) && (udphdr->uh_dport == pair->port0) ){
                udp_streams = malloc(sizeof(struct udp_stream_t)); 
                pair->udp_stream_last->udp_stream_next = udp_streams;
                pair->udp_stream_last = udp_streams;
                udp_streams->udp_stream_next = NULL;
                udp_streams->plist = plist; 
                udp_streams->iphdr = iphdr; 
                udp_streams->udphdr = udphdr;
                udp_streams->direction = 1; /* ��ε� */
                pair->pair_count++;
                return(0);

            }
        } 


        if(pair->pair_next == NULL)
            break;
        pair = pair->pair_next;
    }

	/* �ꥹ�Ȥ˴�¸�� udp port pair ��̵���Τǿ����˥ꥹ�Ȥ��ɲ� */
    pair_write = malloc(sizeof(struct udp_port_pair_t));
    pair_current->pair_next = pair_write;
    for( i = 0 ; i < 4 ; i++){
        pair_write->addr0[i] = iphdr->ip_src[i];
        pair_write->addr1[i] = iphdr->ip_dst[i];
    }
    pair_write->pair_head = pair_head;
    (pair_write->port0) = (udphdr->uh_sport);
    (pair_write->port1) = (udphdr->uh_dport);
    pair_write->pair_next = NULL;
    pair_write->pair_count++;
    pair_write->udp_stream = malloc(sizeof(struct udp_stream_t)); 
    pair_write->udp_stream_last = pair_write->udp_stream;
    pair_write->udp_stream->udp_stream_first = pair_write->udp_stream;
    pair_write->udp_stream->udp_stream_next = NULL;
    pair_write->udp_stream->plist = plist; 
    pair_write->udp_stream->iphdr = iphdr; 
    pair_write->udp_stream->udphdr = udphdr;
    pair_write->udp_stream->direction = 0; /* �ǽ�� packet ���������Ƥ��������� 0 �Ȥ���*/
    pair_current = pair_write;
			
    return(0);
}


/*
 *  plist ��Ȥä� packet ���ɤ�
 */
int read_packet(){
    int i;
    struct     in_addr insaddr, indaddr;
    struct     dgram *dgram;
    struct     tcphdr *tcphdr;
    struct     udphdr *udphdr;

    conn_current = malloc(sizeof(struct connection_t));
    conn_head = conn_current;
        
    pair_current = malloc(sizeof(struct udp_port_pair_t));
    pair_head = pair_current; 

    plist_current = plist_head;
    for ( i = 1 ; i < count + 1 ; i++){
        dgram = (struct dgram *)plist_current->cap_datap;
            /* ether type 0x800=IP �����ɤ� */
        if( check_ethertype(dgram->ether.ether_type) ){

                /* TCP �� packet �����ɤ� */
            if( dgram->ip.ip_p == IPPROTO_TCP){
                if(debug){ /* debug �� */ 
                    printf("==========================================\n");
                    printf("Packet:%d, Len:%d \n",plist_current->packet_number, plist_current->packet_len);
                    printf("EtherType: %x\n",dgram->ether.ether_type);
                    printf("version     : %d\n",dgram->ip.ip_v);
                    printf("header len  : %d\n",dgram->ip.ip_hl);
                    printf("protocol    : %d\n",dgram->ip.ip_p);
                    printf("id          : %d\n",ntohs(dgram->ip.ip_id));
                    printf("check       : %x\n",dgram->ip.ip_sum);
                    printf("saddr       : %d.%d.%d.%d\n",dgram->ip.ip_src[0],dgram->ip.ip_src[1],
                           dgram->ip.ip_src[2],dgram->ip.ip_src[3]);
                    printf("daddr       : %d.%d.%d.%d\n",dgram->ip.ip_dst[0],dgram->ip.ip_dst[1],
                           dgram->ip.ip_dst[2],dgram->ip.ip_dst[3]);
                }
			
                    /* tcp �إå��Υ��ɥ쥹��׻���IP �إå��Υ��ɥ쥹�� ip_hl x 4 byte ��­�� */ 	
                tcphdr = (struct tcphdr *)((char *)&(dgram->ip) + ((dgram->ip.ip_hl)<<2) );

                check_tcp_header(&(dgram->ip),tcphdr,plist_current);	
            }/* if proto == TCP */
            
                /* UDP �� packet �����ɤ� */
            if( dgram->ip.ip_p == IPPROTO_UDP){
                    /* UDP �إå��Υ��ɥ쥹��׻���IP �إå��Υ��ɥ쥹�� ip_hl x 4 byte ��­�� */ 	
                udphdr = (struct udphdr *)((char *)&(dgram->ip) + ((dgram->ip.ip_hl)<<2) );

                check_udp_header(&(dgram->ip),udphdr,plist_current);	
                            
            }/* if proto == UDP */

        } /* if ethertype == ethernet */
        plist_current++;
    }/* for() loop */
}

int read_conn_list(){
	struct connection_t *conn;

	/* conn_head �϶��ʤΤǡ������顦��*/
	conn = conn_head->conn_next ;
	if(conn == NULL )
		return(0);

	printf("\n====================================\n");
	printf("        Connection List              \n");
	for(; conn != NULL ; conn = conn->conn_next ){
		printf("====================================\n");
		printf("addr 0: %d.%d.%d.%d : Port: %d\n",conn->addr0[0],conn->addr0[1],conn->addr0[2],
                       conn->addr0[3],conn->port0);	
		printf("addr 1: %d.%d.%d.%d : Port: %d\n",conn->addr1[0],conn->addr1[1],conn->addr1[2],
                       conn->addr1[3],conn->port1);
		printf("Number of packets  : %d\n", conn->conn_count);
	}

}

int read_pair_list(){
	struct udp_port_pair_t *pair;

	/* pair_head �϶��ʤΤǡ������顦��*/
	pair = pair_head->pair_next ;
	if(pair == NULL )
		return(0);

	printf("\n====================================\n");
	printf("        UPD port pair List              \n");
	for(; pair != NULL ; pair = pair->pair_next ){
		printf("====================================\n");
		printf("addr 0: %d.%d.%d.%d : Port: %d\n",pair->addr0[0],pair->addr0[1],pair->addr0[2],
                       pair->addr0[3],pair->port0);	
		printf("addr 1: %d.%d.%d.%d : Port: %d\n",pair->addr1[0],pair->addr1[1],pair->addr1[2],
                       pair->addr1[3],pair->port1);
		printf("Number of packets  : %d\n", pair->pair_count);
	}

}


int mkbin(){ /* tcp �Υǡ�������� binary file ����*/ 
	struct connection_t *conn;
	struct stream_t *streams;
        double stream_init_time; /* connection ��γ��ϻ���*/
	double receive_time; /* �ġ��� packet ��������� */
	double previous_time = 0; /* ������� packet ��������� */
	FILE *fp0; /* direction 0 �Ѥ� file pointer */
	FILE *fp1; /* direction 1 �Ѥ� file pointer */
	char file0[30]; /* direction 0 �Ѥ� file ̾ */
	char file1[30]; /* direction 1 �Ѥ� file ̾ */
	char tcpdata0[1514]; /* direction 0 �Ѥ� data buffer */
	char tcpdata1[1514]; /* direction 1 �Ѥ� data buffer */
        int tcpdatalen0; /*  direction 0 �� tcp data �� length*/
        int tcpdatalen1; /*  direction 1 �� tcp data �� length*/
        

	/* conn_head �϶��ʤΤǡ������顦��*/
	conn = conn_head->conn_next ;
	if(conn == NULL )
		return(0);


	printf("\n====================================\n");
	printf("     Make binary file from tcp data                   \n");
	printf("====================================\n\n");
	for(; conn != NULL ; conn = conn->conn_next ){

		bzero((char *)file0, sizeof(file0));
		bzero((char *)file1, sizeof(file1));

		printf("\n====================================\n");
		printf("Number of packets  : %d\n\n", conn->conn_count);
		printf("Addr 0: %d.%d.%d.%d : Port: %d\n",
                       conn->addr0[0],conn->addr0[1],conn->addr0[2],conn->addr0[3],conn->port0);
                printf("Addr 1: %d.%d.%d.%d : Port: %d\n",
                       conn->addr1[0],conn->addr1[1],conn->addr1[2],conn->addr1[3],conn->port1);
                    /* file ̾�򥻥å�*/
		sprintf(file0,"%d.%d.%d.%d.%d-%d.%d.%d.%d.%d",conn->addr0[0],conn->addr0[1],conn->addr0[2],conn->addr0[3],
                        conn->port0,conn->addr1[0],conn->addr1[1],conn->addr1[2],conn->addr1[3],conn->port1);
		sprintf(file1,"%d.%d.%d.%d.%d-%d.%d.%d.%d.%d",conn->addr1[0],conn->addr1[1],conn->addr1[2],conn->addr1[3],
                        conn->port1,conn->addr0[0],conn->addr0[1],conn->addr0[2],conn->addr0[3],conn->port0);	

		if (( fp0 = fopen(file0,"wb")) == NULL){
			perror("fopen");
		}
		if (( fp1 = fopen(file1,"wb")) == NULL){
			perror("fopen");
		}

		/* �ʲ� �ġ��� packet �ν��� */
		for( streams = conn->stream ; streams != NULL ; streams = streams->stream_next){
			bzero((char *)tcpdata0,sizeof(tcpdata0));
			bzero((char *)tcpdata1,sizeof(tcpdata1));

			if(streams->direction){
                                /* �ޤ���ip_len �� ip_hl �� th_offset ��ꡢpacket ��Υǡ���Ĺ��׻�*/
                            tcpdatalen1 = TCPLEN(streams);
                                /* TCP header �� address + header len �� address �Υǡ��� ���� buffer �� copy */
                            memcpy(tcpdata1, (char *)streams->tcphdr + ((streams->tcphdr->th_offset)<<2), tcpdatalen1 );
                                /* �ե�����˽񤭹��� */
                            fwrite(tcpdata1,sizeof(char), tcpdatalen1, fp1 );
			} else {
                            tcpdatalen0 = TCPLEN(streams);
                            memcpy(tcpdata0, (char *)streams->tcphdr + ((streams->tcphdr->th_offset)<<2) ,tcpdatalen0 );
                            fwrite(tcpdata0,sizeof(char), tcpdatalen0, fp0 );
			}
				

		}
		fclose(fp0);
		fclose(fp1);
	}
}


/* connection �ꥹ�ȳƥѥ��åȤ�ɽ����
 * ���ץ����ե饰�ˤ�äƤ��̾���Ϥ˲ä��ơ�
 * sequence �ֹ�����å���ɽ�� */
int view_conn(int optflag){ 
    struct connection_t *conn;
    struct stream_t *streams;
    struct stream_t *streams_check;
    int    exp_ack; /* packet �����Ԥ��� ACK �� */
    int    self_seq; /* Sefl packet SEQ �� */
    int    len; /* TCP �� data ��Ĺ��*/
    double stream_init_time; /* connection ��γ��ϻ���*/
    double receive_time; /* �ġ��� packet ��������� */
    double previous_time = 0; /* ������� packet ��������� */
    double acked_elapse ; /* ack �������ޤǤλ��� */
    uint32_t next_seq[2];   /* Diag �Ѥ� ������Υѥ��åȤޤǤ� SEQ �οʹԾ��� */

    

        /* conn_head �϶��ʤΤǡ������顦��*/
    conn = conn_head->conn_next ;
    if(conn == NULL )
        return(0);


    printf("\n====================================\n");
    printf("        Check each connection                \n");
    printf("====================================\n");
    for( ; conn != NULL ; conn = conn->conn_next) {
        printf("\n====================================\n");
        printf("Number of packets  : %d\n\n", conn->conn_count);
        printf("Addr 0: %d.%d.%d.%d : Port: %d",conn->addr0[0],conn->addr0[1],conn->addr0[2],conn->addr0[3],conn->port0);	
        printf("\t\t\t\t\t");
        printf("Addr 1: %d.%d.%d.%d : Port: %d\n",conn->addr1[0],conn->addr1[1],conn->addr1[2],conn->addr1[3],conn->port1);
        printf("---------------------------------------------------------------");
        printf("----------------------------------------------------------------\n");
        stream_init_time = conn->stream->plist->php->pktime.tv_sec + (conn->stream->plist->php->pktime.tv_usec  / 1.0e+6);
        previous_time = stream_init_time;

            /* �ʲ� �ġ��� packet �ν��� */
        for(streams = conn->stream ; streams != NULL ; streams = streams->stream_next ){

            receive_time = streams->plist->php->pktime.tv_sec + (streams->plist->php->pktime.tv_usec  / 1.0e+6);


            INDENT(streams);
            
                /* �ʲ� summary ɽ���� */
            printf("%d: ",streams->plist->packet_number);
            printf("%5.3f ",receive_time - previous_time);
            if (streams->iphdr->ip_off & (8191)){
                /* fragment offset �� 0 �ʳ���fragment���Ƥ��ơ�TCP header ��̵��) IP data gram ��Ƚ��*/
                printf(" IP fragment");
                printf(" IPID: %u",streams->iphdr->ip_id);
                printf(" Len:%4d", IPLEN(streams));                
                printf(" Flag: 0x%x",streams->iphdr->ip_off);
                printf(" Offset: %u",((streams->iphdr->ip_off) & (8191))<<3);
                if (streams->iphdr->ip_off & IP_MF)
                    printf(" MF");
                if (streams->iphdr->ip_off & IP_DF)
                    printf(" DF");
                printf("\n");
            } else {
                /* IP fragment ���Ƥ��ʤ����⤷���Ϻǽ�� fragment �� tcp packet */
                printf("%u",  SEQ(streams));            
                printf("(%u)", ACK(streams));            
                printf(" Win:%d",*((ushort *)(&(streams->tcphdr->th_win))));
                printf(" Len:%4d", TCPLEN(streams));
                printf(" ");            
                if (streams->iphdr->ip_off & IP_MF)
                    printf(" MF");
                if (streams->iphdr->ip_off & IP_DF)
                    printf(" DF");                                            
                printf(" ");
                if(( *(streams->tcphdr->th_flags) | TH_FIN) == *(streams->tcphdr->th_flags))
                    printf("FIN ");
                if(( *(streams->tcphdr->th_flags) | TH_SYN) == *(streams->tcphdr->th_flags))
                    printf("SYN ");
                if(( *(streams->tcphdr->th_flags) | TH_RST) == *(streams->tcphdr->th_flags))
                    printf("RST ");
                if(( *(streams->tcphdr->th_flags) | TH_PUSH) == *(streams->tcphdr->th_flags))
                    printf("PSH ");
                if(( *(streams->tcphdr->th_flags) | TH_ACK) == *(streams->tcphdr->th_flags))
                    printf("ACK ");
                if(( *(streams->tcphdr->th_flags) | TH_URG) == *(streams->tcphdr->th_flags))
                    printf("URG ");
                printf("\n");
            }
            previous_time = receive_time ;            
                //printf("\t\t%s\n",streams->direction ? "<------------------\n" : "------------------>\n");

            
            if(!(optflag & DIAG))
                continue;
                /************** ��������� DIAG �ե饰���Ĥ��Ƥ��������� ******************/

            /* more fragmen ��Ω�äƤ��� packet �� ack ��Ĵ���򤷤ʤ�                             */
            /* �ʤ��ʤ顢fragment ������Ǥϡ�TCP segment �Ȥ��Ƥ� total length ���狼��ʤ��Τ�  */
            if (streams->iphdr->ip_off & IP_MF){
                //INDENT(streams);
                //printf("\t> IP fragment packet.(can't check ack packet)\n");
                continue;
            }
            
            self_seq = SEQ(streams);
            /* len �� fragmen/non-fragment �ѥ��å������� �ǡ���Ĺ������ */
            len = TCPLEN(streams);

            /*
             * SACK(Selective Ack) Option �γ�ǧ
             * TCP �إå���Ĺ�� 5(=20bytes) ����礭����С��ʤ�餫��
             * TCP Option �����ꤵ��Ƥ���
             */
#ifdef SACK
                if( streams->tcphdr->th_offset > 5 ){
                    uint16_t tcphdrlen;
                    char *tcpopt, *tcpopt_head;
                    uint8_t optlen;
                    struct sackval 
                    {
                        uint32_t leftedge;
                        uint32_t rightedge;
                    } *sackval;

                    tcphdrlen = streams->tcphdr->th_offset <<2;
                    
                    tcpopt_head = tcpopt = (char *)streams->tcphdr + 20 ; 
                    while(*tcpopt != NULL && (tcpopt - tcpopt_head) < tcphdrlen - 20){
                        
                        switch(*tcpopt){
                            case 1: /* NOP������option ��*/
                                tcpopt++; 
                                if (debug) { INDENT(streams); printf("\t> NOP option found\n");}
                                break;
                            case 4: /* SACK Permitted option */
                                tcpopt = tcpopt + 2; /* SACK OK option ���� option �� */
                                INDENT(streams);                                                                
                                printf("\t> sack-permitted option found\n");
                                break;                                
                            case 5: /* SACK OPTION */{
                                int i;
                                char *pointer; /* �����ѤΥݥ��� */

                                pointer = tcpopt + 1 + 1; /* type �� lenght ��ʬ��ʤ��*/
                                optlen = *(uint8_t *)(tcpopt + 1);
                                sackval = malloc(sizeof(struct sackval));

                                /*
                                 * Left edge �� Right edige �Υڥ�(8bytes)���Ҥ��äƤ��롣
                                 * optlen -2 / 8 ��ʬ�����롼��
                                 */
                                for ( i = optlen - 2 ; i > 0 ; i = i - 8){
                                    memcpy(sackval, pointer, 8);
                                    INDENT(streams);                                
                                    printf("\t> sack = %u - %u\n", sackval->leftedge, sackval->rightedge);
                                    pointer = pointer + 8;
                                }
                                tcpopt = tcpopt + optlen;
                                free(sackval); /* �⤦�Ȥ�ʤ��Τ� free */
                                break;
                            }
                            default : /* ¾�� Option */
                                if (debug){ INDENT(streams); printf("\t> TCP option found\n");}
                                optlen = *(uint8_t *)(tcpopt + 1); 
                                tcpopt = tcpopt + optlen; 
                                break;
                        } /* switch end */
                    } /* while end */
                } /* if tcphdr > 20 end */
#endif /* SACK */
            
            
            /* ���ˤ���ȴ��Ԥ���Ƥ��� SEQ �ȡ����Υѥ��åȤ� SEQ �����
             * �⤷�������ͤ����礭����С����֤������ؤ�ä������ޤ���
             * �ѥ��åȤΥɥ�åפβ�ǽ�������� */
            if(conn->snd_nxt[streams->direction] == 0)
            {
                    /* ���Ԥ��� SEQ(SND_NXT)�� 0 �Ĥޤꤳ���� snoop �ǤΤ��� TCP */
                    /* connction �κǽ�� packet ��������������                  */
                conn->snd_nxt[streams->direction] =
                    SEQ(streams) + len + SYNFIN(streams);
            }
            else
            {

                next_seq[streams->direction] = conn->snd_nxt[streams->direction];
                if( next_seq[streams->direction] < SEQ(streams))
                {
                        /* ���Ԥ��Ƥ����ꡢ�礭�� SEQ �ֹ椬���� */
                    INDENT(streams);
                    printf("\t> out of order data packet. expected SEQ = %u\n",next_seq[streams->direction]);
                    
                }
                else if (next_seq[streams->direction] == SEQ(streams)){
                    /* �����̤�Υѥ��åȤ��褿��snd_nxt �򹹿�                       */
                    conn->snd_nxt[streams->direction] = SEQ(streams) + len + SYNFIN(streams);
                }
                else{
                        /* �����ͤ��⾮���� SEQ��������*/
                    INDENT(streams);
                    printf("\t> retransmission packet?\n");
                }


                /* ������ packet �� SND_NXT �� SEQ ���ޤޤ�Ƥ��뤫Ĵ�٤� & �����Υ����å�*/
                /* �����ϥǡ����������� packet ���̤뤿�ᡢ������٤��⤤���ײ���         */
                if( len > 0){
                    for(streams_check =  conn->stream ; streams_check != streams ; streams_check = streams_check->stream_next){
                         /* Self packet �Τߤ�����å�*/
                        if (streams_check->direction != streams->direction) 
                            continue;
                        /* last fragment(IP_MF ��Ω�äƤʤ�)�ѥ��åȤΤߤ�����å� */
                        if (streams_check->iphdr->ip_off & IP_MF) 
                            continue;


                        /* �ǡ��������äơ�SEQ �� SND_NXT ��Ʊ�� packet ��Ĵ�٤�*/	
                        if ( TCPLEN(streams_check) > 0 && SEQ(streams_check) == conn->snd_nxt[streams->direction]){
                            conn->snd_nxt[streams->direction] =
                                SEQ(streams_check) + TCPLEN(streams_check)  + SYNFIN(streams_check);
                            INDENT(streams);
                            printf("\t> SEQ = %u was already sent by pakcet %d\n",
                                   SEQ(streams_check), streams_check->plist->packet_number);
                                /* �ޤ���¾�ˤ⤢�뤫�⤷��ʤ��Τǡ��ǽ餫��Ĵ��ľ����*/
                            streams_check = conn->stream;
                            continue;
                        }
                        /* SEQ ��Ʊ���ǡ��ǡ�������äƤ��� packet ��Ĵ�٤�*/	
                        if( (SEQ(streams_check) == self_seq) && (TCPLEN(streams_check) != 0)){
                            INDENT(streams);
                            printf("\t> may retransmission packet of packet%d\n",streams_check->plist->packet_number);
                        }
                    } /* ������ packet �Υ����å��Υ롼�׽����*/
                } /* �⤷�ǡ��������ä��顦��*/
                
            }/* if SND_NXT == 0 else .. end */

            
            if(streams->stream_next == NULL){ /* �Ĥ��� packet ��̵��*/
                INDENT(streams);
                printf("\t> ...won't check ack packet. No more packets\n");
                continue;
            }            

                /* �ޤ���ACK ��ɬ�פ��ɤ����ʥǡ���ͭ�ꡢ�ޤ��� FIN or SYN)���ǧ */
                /* ɬ��̵����С�¾�� packet ��Ĵ�٤ʤ���ɬ�פʤ鼡�� for() �롼�פ�    */
            if(len != 0){ /* �ǡ�����̵ͭ */
                exp_ack = SEQ(streams) + len ; 

                if( *(streams->tcphdr->th_flags) & (TH_FIN | TH_SYN)){ /* �ǡ��������ꡢ���  FIN or SYN �ξ�� */
                    exp_ack++;
                    if(debug) printf("\t\texp_ack(len & FIN/SYN) = %d packet %d\n",exp_ack,streams->plist->packet_number);
                }
                if(debug) printf("\t\texp_ack(len) = %d Packet %d\n",exp_ack,streams->plist->packet_number);
            } else {
                if( *(streams->tcphdr->th_flags) & (TH_FIN | TH_SYN)){ /* FIN or SYN �ξ�� */
                    exp_ack = SEQ(streams) + 1;
                    if(debug) printf("\t\texp_ack(FIN/SYN) = %d packet %d\n",exp_ack,streams->plist->packet_number);
                } else {
                        /* ������ ACK �ѥ��åȡ��ʤΤǡ��ʲ���ACK �Υ����å��⡢�����Υ����å���Ԥ�ʤ�*/
                    INDENT(streams);
                    printf("\t> doesn't expect to be acked\n");
                    continue;
                }
            }

                /* ³���� packet ������Ԥ��� ACK �����뤫�ɤ����� check */

            for(streams_check = streams->stream_next ; streams_check != NULL ; streams_check = streams_check->stream_next){
                
                if (streams_check->direction == streams->direction){ /* ��꤫��� packet �Τߤ�����å�*/
                    if(streams_check->stream_next == NULL){ /* �⤷���줬�Ǹ�� packet �ʤ� ACK ����Ƥ��ʤ��ȸ�������*/
                        INDENT(streams);                        
                        printf("\t> not acked!!!\n");
                    }
                    continue;
                }
                

                /* ��꤫��� packet �� fragment ��̵ͭ������å�����ɬ�פ�̵����*/
                    /* ���Ԥ��� ack ���� packet ��Ĵ�٤�*/	
                if( ACK(streams_check) == exp_ack ){
                    acked_elapse = streams_check->plist->php->pktime.tv_sec + (streams_check->plist->php->pktime.tv_usec / 1.0e+6);
                    INDENT(streams);
                    printf("\t> exactly acked by %d(%f Sec)\n",
                           streams_check->plist->packet_number, acked_elapse - receive_time);
                    break;
                } else if (ACK(streams_check) > exp_ack ){
                    acked_elapse = streams_check->plist->php->pktime.tv_sec + (streams_check->plist->php->pktime.tv_usec / 1.0e+6);
                    INDENT(streams);
                    printf("\t> acked by %d(%f Sec)\n",
                           streams_check->plist->packet_number,acked_elapse - receive_time);
                    break;
                }

                if(streams_check->stream_next == NULL){ /* �Ǹ�ޤ��褿�� ACK ����Ƥ��ʤ��ȸ�������*/
                    INDENT(streams);
                    printf("\t> not acked!!!\n");
                }
                
				
            } /* loop for searching ack end */
        } /* loop for stream end */
    } /* loop for connection list end */
}


/* UDP port pair �ꥹ�ȳƥѥ��åȤ�ɽ����*/
int view_pair(int optflag){ 
    struct udp_port_pair_t *pair;
    struct udp_stream_t *udp_streams;
    struct udp_stream_t *udp_streams_check;
    double udp_stream_init_time; /* UDP port pair ��γ��ϻ���*/
    double receive_time; /* �ġ��� packet ��������� */
    double previous_time = 0; /* ������� packet ��������� */
    

        /* pair_head �϶��ʤΤǡ������顦��*/
    pair = pair_head->pair_next ;
    if(pair == NULL )
        return(0);


    printf("\n====================================\n");
    printf("        Check each UDP port pair                \n");
    printf("====================================\n");
    for( ; pair != NULL ; pair = pair->pair_next) {
        printf("\n====================================\n");
        printf("Number of packets  : %d\n\n", pair->pair_count);
        printf("Addr 0: %d.%d.%d.%d : Port: %d",pair->addr0[0],pair->addr0[1],pair->addr0[2],pair->addr0[3],pair->port0);
        printf("\t\t\t\t\t");
        printf("Addr 1: %d.%d.%d.%d : Port: %d\n",pair->addr1[0],pair->addr1[1],pair->addr1[2],pair->addr1[3],pair->port1);
        printf("---------------------------------------------------------------");
        printf("----------------------------------------------------------------\n");
        udp_stream_init_time = pair->udp_stream->plist->php->pktime.tv_sec +
            (pair->udp_stream->plist->php->pktime.tv_usec  / 1.0e+6);
        previous_time = udp_stream_init_time;

            /* �ʲ� �ġ��� packet �ν��� */
        for(udp_streams = pair->udp_stream ; udp_streams != NULL ; udp_streams = udp_streams->udp_stream_next ){

            receive_time = udp_streams->plist->php->pktime.tv_sec + (udp_streams->plist->php->pktime.tv_usec  / 1.0e+6);


            INDENT(udp_streams);
            
                /* �ʲ� summary ɽ���� */
            printf("%d: ",udp_streams->plist->packet_number);
            printf("%5.3f ",receive_time - previous_time);
            printf(" IPID: %u",udp_streams->iphdr->ip_id);
            printf(" Len:%4d", UDPLEN(udp_streams));
            printf("  ");
            printf(" Flag: 0x%x",udp_streams->iphdr->ip_off);
            printf(" Offset: %u",((udp_streams->iphdr->ip_off) & (8191))<<3);
            if (udp_streams->iphdr->ip_off & IP_MF)
                printf(" MF");
            if (udp_streams->iphdr->ip_off & IP_DF)
                printf(" DF");                                

            previous_time = receive_time ;
            printf("\n");
            
            if(!(optflag & DIAG))
                continue;
				
        } /* loop for udp_stream end */
    } /* loop for UDP port pair list end */
}


/*
 * ether header �� type �ե�����ɤ��ɤ�ǡ�type ���̡�
 * IP �λ����� 1 ���֤�
 * �ޤ���802.3 �ե졼��ξ��ϡ������̽����ء�̤������
 */
int check_ethertype(int type)
{
  switch(type){
  case ETHERTYPE_IP : 
    return (1);
    break;
  case ETHERTYPE_ARP :
    return (0);
    break;
  case ETHERTYPE_REVARP :
    return (0);
    break;
  }
  if (type < 1500)
    return (0);
  return (0);
}

int
main(int argc, char *argv[])
{
	int i;
	struct plist *plist_current;

        int optflag = 0;
        
	char *file_name;

	if (argc < 2) {
		printf("Usage: %s [ -ldvb ] <file name>\n",argv[0]); 
		printf("             -l : view connections list\n"); 
		printf("             -d : view packet with Seq+Ack diagnosis\n"); 
		printf("             -v : view packet\n");
                printf("             -b : make tcp data files\n");
		printf("             -u : view UDP packet\n");                                
		exit(0);
	}

	while ((i = getopt (argc, argv, "ludbv:")) != EOF) {
		switch (i){
			case 'l':
				optflag |= LIST;	
				break;

			case 'd':
				optflag |= DIAG;
				break;

			case 'v':
                                optflag |= VIEW;
				break;
                                
			case 'b':
                                optflag |= BIN;	
				break;
                                
			case 'u':
                                optflag |= VIEWUDP;	
				break;                                

			default:
				printf("Usage: %s [ -ldv ] <file name> \n",argv[0]); 
				printf("             -l : view connections list\n"); 
				printf("             -d : view packet with Seq+Ack diagnosis\n"); 
				printf("             -v : view packet \n");
                                printf("             -b : make tcp data files\n");
                                printf("             -u : view UDP packet\n");                                
				exit(0);
		}
	}

	/*
	 * snoop �ե������ open ɬ��
	 */
	if(argc == 3)
		file_name = argv[2];
	else
		file_name = argv[1];

	if( sn_open(file_name) < 0){
		perror("sn_open()");
		exit(0);
	}


	/*
	 * packet ��(count)������ ɬ��
	 */
	if (sn_count() < 0){
		perror("sn_count()");
		exit(0);
	}

	
	/*
	 * packet �Υꥹ��(plist_head)������ ɬ��
	 */
	if ( get_plist() < 0){
		perror("get_plist()");
		exit(0);
	}

	/*
	 * packet ���ɤ� ɬ��
	 */
	if ( read_packet() < 0){
		perror("read_packet()");
		exit(0);
	}

	/*
	 *  connection list 
	 *  �� udp port pair list �򸫤� ���ץ����
         */
	if(optflag & LIST){
		if ( read_conn_list() <0 ) { 
			perror("read_conn_list()");
			exit(0);
		}
		if ( read_pair_list() <0 ) { 
			perror("read_pair_list()");
			exit(0);
		}                
              
	}

	/*
	 *  �� connection �� packet ��ή���ɽ�� ���ץ����
	 *  �ɲå��ץ����ˤ�äơ�packet �� ack ���ǧ����Ԥ�
         */
	if(optflag & (VIEW|DIAG)){
		if ( view_conn(optflag) < 0 ) { 
			perror("view_conn()");
			exit(0);
		}
	}
        
	/*
	 *  �� UDP port pair �� packet ��ή���ɽ�� ���ץ����
	 *  �ɲå��ץ����Ϥޤ�̤����
         */
	if(optflag & (VIEWUDP)){
		if ( view_pair(optflag) < 0 ) { 
			perror("view_pair()");
			exit(0);
		}
	}        

	/*
	 *  �� connection �� ��������� TCP �� data ����ե�����Ȥ�����¸��
	 *  file ̾ �� <src IP>.<src port>-<dest IP>.<dest port>
         */
	if(optflag & BIN){
		if ( mkbin() <0 ) { 
			perror("mkbin()");
			exit(0);
		}
	}
	return (0);
}

