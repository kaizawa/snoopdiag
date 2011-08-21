/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1986, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Copright (c) 2010  Kazuyoshi Aizawa <admin2@whiteboard.ne.jp>
 * All rights reserved.
 */   

/*
 * Tools that diagnose tcp/udp packets captured using Solaris's snoop(1M) command. 
 *
 * See RFC 1761 Snoop Packet Capture File Format
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <strings.h> 
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/signal.h>
#include <string.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#ifdef SNOOPDIAG_SUNOS
#include <sys/types32.h>
#endif

#define	SNOOP_V2          2
#define DL_ETHER        0x4     /* Ethernet Bus */

#define LIST  0x1	     /* connection list output */
#define VIEW  0x1<<1	     /* view output */
#define DIAG  0x1<<2	     /* packet view with statistics output */
#define BIN   0x1<<3         /* make TCP data files */
#define VIEWUDP   0x1<<4     /* view udp packet pair */
#define VERBOSE   0x1<<5     /* Print verbose outputs */

/*
 * Linux doesn't hae 32bit timeval structure.
 */
#ifdef SNOOPDIAG_LINUX
struct timeval32 {
        time32_t        tv_sec;         /* seconds */
        int32_t         tv_usec;        /* and microseconds */
};
#endif

/*
 * Sequence number、Ack number を得るマクロ
 */
#define SEQ(stream) ntohl(stream->tcphdr->th_seq)
#define ACK(stream) ntohl(stream->tcphdr->th_ack)

/*
 * TCP のデータ長を得る。Fragment Packet の場合は IP のデータ長を返す
 */ 
#define TCPLEN(stream)  ntohs(stream->ip->ip_off) & (8191) ? TCPFRAGMENTLEN(stream) : TCPNONFRAGMENTLEN(stream) 
#define TCPNONFRAGMENTLEN(stream) ntohs(stream->ip->ip_len) - (stream->ip->ip_hl<<2) - (stream->tcphdr->th_off<<2)
#define TCPFRAGMENTLEN(stream) ((ntohs(stream->ip->ip_off) & (8191))<<3) + IPLEN(stream) - (stream->ip->ip_hl<<2)

/*
 * UDP のデータ長を得る。Fragment Packet の場合は IP のデータ長を返す
 */ 
#define UDPLEN(stream) (ntohs(stream->ip->ip_off) & (8191) ? UDPFRAGMENTLEN(stream) : UDPNONFRAGMENTLEN(stream))
#define UDPNONFRAGMENTLEN(stream) (ntohs(stream->ip->ip_len) - (stream->ip->ip_hl<<2) - 8)
#define UDPFRAGMENTLEN(stream) (IPLEN(stream))

/*
 * IP のデータ長を得る
 */
#define IPLEN(stream)  ntohs(stream->ip->ip_len) - (stream->ip->ip_hl<<2)

/*
 * Packet の方向によって出力表示位置（右or左）を変えるためのマクロ
 */
#define INDENT(stream)     if(stream->direction) printf("\t\t\t\t\t\t\t\t\t");

/*
 * SYN もしくは FIN フラグが立っているかどうかを確認する
 * フラグがたっていれば 1, 立っていなければ 0 を返す。
 */
#define SYNFIN(tcphdr) (tcphdr->th_flags & (TH_FIN | TH_SYN) ? 1 : 0)

/*
 * timeval 構造体から秒を算出する
 */
#define TIMEVAL_TO_SEC(pktime) ntohl(pktime.tv_sec) + (ntohl(pktime.tv_usec) / 1.0e+6)

/*
 * 各 connection 内の Packet の plist のアドレスを格納した構造体
 */
typedef struct stream stream_t;
struct stream {
    stream_t *stream_first;  /* connection の最初の stream_t 構造体 */ 
    stream_t *stream_next;   /* 次の packet の stream_t 構造体 */
    struct plist *plist;     /* plist 構造体へのポインタ */
    struct ip *ip;           /* IP ヘッダのポインタ */
    struct tcphdr *tcphdr;   /* TCP ヘッダのポインタ */
    int    direction;        /* 処理上 0 or 1 で packet の送信方向を特定する */ 
};

/*
 * TCP の 1 connection 毎の構造体
 */
typedef struct connection connection_t;
struct connection {
    connection_t *conn_head; /* connection list の先頭　*/
    connection_t *conn_next; /* connection list の 次の構造体 */
    struct in_addr addr0;               /* connection の 片側の IP */
    struct in_addr addr1;               /* connection の もう片側の IP */
    uint16_t port0;                 /* connection の 片側の port */
    uint16_t port1;                 /* connection の もう片側の port */
    int conn_count;                 /* この connection の Packet 数 */
    stream_t *stream;        /* この connection の最初のPacketの stream_t 構造体へのポインタ*/ 
    stream_t *stream_last;   /* この connection の最後Packetの stream_t 構造体へのポインタ*/
    uint32_t snd_nxt[2] ;           /* Diag 時用の SEQ の進行状況。双方向に用意*/
};
connection_t *conn_current, *conn_write, *conn_head;

/*
 * UDP の port ペア 毎の構造体
 */
struct udp_port_pair_t{
    struct udp_port_pair_t *pair_head; /* udp port pair list の先頭　*/
    struct udp_port_pair_t *pair_next; /* udp port pair list の 次の構造体 */
    struct in_addr addr0;               /* udp port pair の 片側の IP */
    struct in_addr addr1;               /* udp port pair の もう片側の IP */
    uint16_t port0;                 /* udp port pair の 片側の port */
    uint16_t port1;                 /* udp port pair の もう片側の port */
    int pair_count;                 /* この udp port pair の Packet 数 */
    struct udp_stream_t *udp_stream;        /* この udp port pair の最初のPacketの udp_stream_t 構造体へのポインタ*/ 
    struct udp_stream_t *udp_stream_last;   /* この udp port pair の最後Packetの udp_stream_t 構造体へのポインタ*/
}; 
struct udp_port_pair_t *pair_current, *pair_write, *pair_head;

/*
 * 各 udp port pair 内の Packet の plist のアドレスを格納した構造体
 */
struct udp_stream_t{
	struct udp_stream_t *udp_stream_first;  /* udp port pair の最初の udp_stream_t 構造体 */ 
	struct udp_stream_t *udp_stream_next;   /* 次の packet の udp_stream_t 構造体 */
	struct plist *plist;            /* plist 構造体へのポインタ */
	struct ip *ip;            /* IP ヘッダのポインタ */
        struct udphdr *udphdr;          /* UDP ヘッダのポインタ */
	int    direction;               /* 処理上 0 or 1 で packet の送信方向を特定する */ 
};

/*
 *  Structure for snoop file header 
 */
struct snoop_fheader {
	char name[8];
	uint32_t version;
	uint32_t mactype;
} *fhp; 

/*
 * Structure for each packet record included in snoop file.
 */
struct snoop_pheader {
        uint32_t       pktlen;		/* length of original packet */
	uint32_t       caplen;		/* length of packet captured into file */
	uint32_t       reclen;		/* length of this packet record */
	uint32_t       drops;		/* cumulative drops */
	struct timeval32 pktime;	        /* packet arrival time */
}; 

/*
 * 各 packet 処理用の構造体
 */
struct plist {
	int			packet_number;
        struct plist		*first;        /* plist_head へのポインタ*/
        struct plist		*nextpkt;      /* 次の plist 構造体へのポインタ*/
	struct snoop_pheader	*php;          /* snoop_pheader 構造体へのポインタ*/
        int             	packet_len;    /* 実 packet 長*/
	char			*cap_datap;    /* 実 packet へのポインタ*/
};
struct plist *plist_head;                  /* packet list 構造体の先頭へのポインタ */

int count=0; /* 総 packet 数 */
int bufflen;
char *buffp;
int optflag;

int sn_open(char *);
int sn_count();
int get_plist();
int check_tcp_header(struct ip *, struct tcphdr *, struct plist *);
int check_udp_header(struct ip *, struct udphdr *, struct plist *);
int read_packet();
int read_conn_list();
int read_pair_list();
int mkbin();
int view_conn();
int view_pair();
int check_ethertype(int);
void print_usage(char *);

int
main(int argc, char *argv[])
{
	int i;
	char *file_name;

	if (argc < 2) {
            print_usage(argv[0]);
            exit(1);
	}

	while ((i = getopt (argc, argv, "Dludbv")) != EOF) {
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

			case 'D':
                                optflag |= VERBOSE;	
				break;                                

			default:
                            print_usage(argv[0]);
                            exit(0);
		}
	}

	/*
	 * snoop ファイルを open 必須
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
	 * packet 数(count)を得る 必須
	 */
	if (sn_count() < 0){
		perror("sn_count()");
		exit(0);
	}
	
	/*
	 * packet のリスト(plist_head)を得る 必須
	 */
	if ( get_plist() < 0){
		perror("get_plist()");
		exit(0);
	}

	/*
	 * packet を読む 必須
	 */
	if ( read_packet() < 0){
		perror("read_packet()");
		exit(0);
	}

	/*
	 *  connection list 
	 *  と udp port pair list を見る オプション
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
	 *  各 connection の packet の流れを表示 オプション
	 *  追加オプションによって、packet の ack を確認等を行う
         */
	if(optflag & (VIEW|DIAG)){
		if ( view_conn() < 0 ) { 
			perror("view_conn()");
			exit(0);
		}
	}
        
	/*
	 *  各 UDP port pair の packet の流れを表示 オプション
	 *  追加オプションはまだ未実装
         */
	if(optflag & (VIEWUDP)){
		if ( view_pair(optflag) < 0 ) { 
			perror("view_pair()");
			exit(0);
		}
	}        

	/*
	 *  各 connection の 各方向毎の TCP の data 部をファイルとして保存。
	 *  file 名 は <src IP>.<src port>-<dest IP>.<dest port>
         */
	if(optflag & BIN){
		if ( mkbin() <0 ) { 
			perror("mkbin()");
			exit(0);
		}
	}
	return (0);
}

/*
 * snoop ファイルの open 処理
 */
int
sn_open(char *file_name)
{
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
	 * snoop ファイルをメモリに読み込む
	 */
	p = mmap(0, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (p == (char *)-1) {
		perror("mmap error");
		return (-1);
	}
	printf("mmap size(for caputer file): %lld\n",st.st_size);        

	buffp = p;

	fhp = (struct snoop_fheader *)buffp;

	/*
	 * snoop の header ヘッダーを確認する
	 */
	if (strcmp((char *)"snoop", (char *)fhp->name) != 0 ||
	    htonl(fhp->version) != SNOOP_V2 ||
	    htonl(fhp->mactype) != DL_ETHER) {
		perror("Not a snoop file!:");
		return (-1);
	}
	printf("File Check OK.\n");

	/*
	 * ファイルヘッダを除いた実データの address と、データ長を得る
	 */
	bufflen = st.st_size - sizeof(struct snoop_fheader);
	buffp =  buffp + sizeof(struct snoop_fheader);
	printf("data size: %d\n",bufflen);
	return (0);
}

/*
 * packet 数をカウント処理 -D オプションをつければ 各 packet の長さと、経過時間も出力可能）
 */
int
sn_count()
{
    double  initial_time;
    int data_size;
    struct snoop_pheader *php; 

    php = (struct snoop_pheader *)buffp;
    data_size = bufflen;
    initial_time = TIMEVAL_TO_SEC(php->pktime);

    printf("Counting numbers of the packets ....");
    while(data_size){
        if(optflag & VERBOSE) printf("Packet Len: %u Time: %f\n", ntohl(php->pktlen), TIMEVAL_TO_SEC(php->pktime) - initial_time);
        data_size -= ntohl(php->reclen);
        php =  (struct snoop_pheader *)((unsigned char *)php + ntohl(php->reclen));
        count++;
    }
    printf("Done\n");

    printf("Number of Packets: %d\n",count);
    return(0);
}

/*
 *  各 packet の情報を線形リスト plist へ格納
 */
int 
get_plist(){
	int i;
        struct snoop_pheader *php;
        struct plist *plist_current, *plist_write; /* 処理用の packet list 構造体 */        
        
	printf("malloc size(for packet list): %zd\n",sizeof(struct plist)*count);

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
		plist_write->packet_len = ntohl(php->pktlen); 
		plist_write->cap_datap = (char *)((unsigned char *)php + sizeof(struct snoop_pheader)); 
		plist_current = plist_write;
		plist_current->nextpkt = ++plist_write;
		php =  (struct snoop_pheader *)((unsigned char *)php + ntohl(php->reclen));
	} 
	plist_current->nextpkt = NULL; /* リストの最後の next pointer は NULL */
        printf("Done\n");

	return(0);

}

/* ip, tcp ヘッダの内容を確認し、connection 毎のグループを作る*/
int
check_tcp_header(struct ip *ip, struct tcphdr *tcphdr, struct plist *plist)
{
    int i;
    connection_t *conn;
    stream_t *streams;

    

    conn = conn_head;
    /*
     * IP address  と TCP port の組み合わせから、既存の connection list の有無を確かめる
     */
    while (1){
        /*
         * fragment offset が 0 以外（fragmentしている) IP data gram を判定。
         * 最初の fragment は TCP ヘッダが付いているので、ここを通過する必要は無い
         */
        if (ntohs(ip->ip_off) & (8191)){
            if (
                ip->ip_src.s_addr == conn->addr0.s_addr &&
                ip->ip_dst.s_addr == conn->addr1.s_addr ||
                ip->ip_src.s_addr == conn->addr1.s_addr &&
                ip->ip_dst.s_addr == conn->addr0.s_addr
                ){
                for (streams = conn->stream ; streams != NULL ; streams = streams->stream_next){
                    /*
                     * 同じ IPID をもつ packet を探す
                     */
                    if( ntohs(ip->ip_id) == ntohs(streams->ip->ip_id)){
                        /*
                         * TCP ヘッダーを 見つかった fragment の最初の packet の TCP ヘッダーとする
                         */
                        tcphdr = streams->tcphdr;
                        break;
                    }
                }
            }
        }

        if (ip->ip_src.s_addr == conn->addr0.s_addr && (ntohs(tcphdr->th_sport) == conn->port0) ){
            if  ( ip->ip_dst.s_addr == conn->addr1.s_addr && (ntohs(tcphdr->th_dport) == conn->port1) ){
                streams = malloc(sizeof(stream_t)); 
                conn->stream_last->stream_next = streams;
                conn->stream_last = streams;
                streams->stream_next = NULL;
                streams->plist = plist; 
                streams->ip = ip; 
                streams->tcphdr = tcphdr;
                streams->direction = 0; /* source と addr0 の ip が 同じなので direction は 0 */
                conn->conn_count++;
                return(0);
            }
        } else if (ip->ip_src.s_addr == conn->addr1.s_addr && (ntohs(tcphdr->th_sport) == conn->port1) ){
            if  (ip->ip_dst.s_addr == conn->addr0.s_addr && (ntohs(tcphdr->th_dport) == conn->port0) ){
                streams = malloc(sizeof(stream_t)); 
                conn->stream_last->stream_next = streams;
                conn->stream_last = streams;
                streams->stream_next = NULL;
                streams->plist = plist; 
                streams->ip = ip; 
                streams->tcphdr = tcphdr;
                streams->direction = 1; /* 上の逆 */
                conn->conn_count++;
                return(0);

            }
        } 

        if(conn->conn_next == NULL)
            break;
        conn = conn->conn_next;
    }

    /* リストに既存の connection が無いので新規にリストに追加 */
    conn_write = malloc(sizeof(connection_t));
    conn_current->conn_next = conn_write;
    conn_write->addr0.s_addr = ip->ip_src.s_addr;
    conn_write->addr1.s_addr = ip->ip_dst.s_addr;
    conn_write->conn_head = conn_head;
    conn_write->port0 = ntohs(tcphdr->th_sport);
    conn_write->port1 = ntohs(tcphdr->th_dport);
    conn_write->conn_next = NULL;
    conn_write->conn_count++;
    conn_write->snd_nxt[0] = 0;
    conn_write->snd_nxt[1] = 0;                
    conn_write->stream = malloc(sizeof(stream_t)); 
    conn_write->stream_last = conn_write->stream;
    conn_write->stream->stream_first = conn_write->stream;
    conn_write->stream->stream_next = NULL;
    conn_write->stream->plist = plist; 
    conn_write->stream->ip = ip; 
    conn_write->stream->tcphdr = tcphdr;
    conn_write->stream->direction = 0; /* 最初に packet を送信してきた方向を 0 とする*/
    conn_current = conn_write;
			
    return(0);
}

/* ip, udp ヘッダの内容を確認し、udp session 毎のグループを作る*/
int check_udp_header(struct ip *ip, struct udphdr *udphdr, struct plist *plist){
    int i;
    struct udp_port_pair_t *pair;
    struct udp_stream_t *udp_streams;

    pair = pair_head;
    
        
	/* IP address  と UDP port の組み合わせから、既存の udp port pair list の有無を確かめる */
    while (1){

        /* fragment offset が 0 以外（fragmentしている) IP data gram を判定*/
        /* 最初の fragment は UDP ヘッダが付いているので、ここを通過する必要は無い*/
        if (ntohs(ip->ip_off) & (8191)){
            
            if (
                ip->ip_src.s_addr == pair->addr0.s_addr &&
                ip->ip_dst.s_addr == pair->addr1.s_addr ||
                ip->ip_src.s_addr == pair->addr1.s_addr &&
                ip->ip_dst.s_addr == pair->addr0.s_addr
                ){

                for (udp_streams = pair->udp_stream ; udp_streams != NULL ; udp_streams = udp_streams->udp_stream_next){
                        /* 同じ IPID をもつ packet を探す*/
                    if(ntohs(ip->ip_id) == ntohs(udp_streams->ip->ip_id)){
                            /* UDP ヘッダーを 見つかった fragment の最初の packet の UDP ヘッダーとする*/
                        udphdr = udp_streams->udphdr;
                        break;
                    }
                }
            }
        }
        
        if ( ip->ip_src.s_addr == pair->addr0.s_addr && (ntohs(udphdr->uh_sport) == pair->port0) ){
            if  ( ip->ip_dst.s_addr == pair->addr1.s_addr && (ntohs(udphdr->uh_dport) == pair->port1) ){
                udp_streams = malloc(sizeof(struct udp_stream_t)); 
                pair->udp_stream_last->udp_stream_next = udp_streams;
                pair->udp_stream_last = udp_streams;
                udp_streams->udp_stream_next = NULL;
                udp_streams->plist = plist; 
                udp_streams->ip = ip; 
                udp_streams->udphdr = udphdr;
                udp_streams->direction = 0; /* source と addr0 の ip が 同じなので direction は 0 */
                pair->pair_count++;
                return(0);
            }
        } else if (ip->ip_src.s_addr == pair->addr1.s_addr && (ntohs(udphdr->uh_sport) == pair->port1) ){
            if  (ip->ip_dst.s_addr == pair->addr0.s_addr && ntohs(udphdr->uh_dport) == pair->port0){
                udp_streams = malloc(sizeof(struct udp_stream_t)); 
                pair->udp_stream_last->udp_stream_next = udp_streams;
                pair->udp_stream_last = udp_streams;
                udp_streams->udp_stream_next = NULL;
                udp_streams->plist = plist; 
                udp_streams->ip = ip; 
                udp_streams->udphdr = udphdr;
                udp_streams->direction = 1; /* 上の逆 */
                pair->pair_count++;
                return(0);

            }
        } 


        if(pair->pair_next == NULL)
            break;
        pair = pair->pair_next;
    }

    /*
     * リストに既存の udp port pair が無いので新規にリストに追加
     */
    pair_write = malloc(sizeof(struct udp_port_pair_t));
    pair_current->pair_next = pair_write;
    pair_write->addr0.s_addr = ip->ip_src.s_addr;    
    pair_write->addr1.s_addr = ip->ip_dst.s_addr;
    pair_write->pair_head = pair_head;
    (pair_write->port0) = ntohs(udphdr->uh_sport);
    (pair_write->port1) = ntohs(udphdr->uh_dport);
    pair_write->pair_next = NULL;
    pair_write->pair_count++;
    pair_write->udp_stream = malloc(sizeof(struct udp_stream_t)); 
    pair_write->udp_stream_last = pair_write->udp_stream;
    pair_write->udp_stream->udp_stream_first = pair_write->udp_stream;
    pair_write->udp_stream->udp_stream_next = NULL;
    pair_write->udp_stream->plist = plist; 
    pair_write->udp_stream->ip = ip; 
    pair_write->udp_stream->udphdr = udphdr;
    pair_write->udp_stream->direction = 0; /* 最初に packet を送信してきた方向を 0 とする*/
    pair_current = pair_write;
			
    return(0);
}

/*
 *  plist を使って packet を読む
 */
int
read_packet()
{
    int i,j;
    struct     in_addr insaddr, indaddr;
    struct     ether_header *ether;    
    struct     ip     *ip;
    struct     tcphdr *tcphdr;
    struct     udphdr *udphdr;
    uint32_t     iplen; /* calcurated ip length including ip header and payload */
    struct     plist *plist_current; /* 処理用の packet list 構造体 */
    unsigned char    *p;

    conn_current = malloc(sizeof(connection_t));
    conn_head = conn_current;
        
    pair_current = malloc(sizeof(struct udp_port_pair_t));
    pair_head = pair_current; 

    plist_current = plist_head;
    for ( i = 1 ; i < count + 1 ; i++){
        ether = (struct ether_header *)plist_current->cap_datap;

        /*
         * ether type 0x800=IP だけ読む
         */
        if( check_ethertype(ntohs(ether->ether_type)) ){
            /*
             * IP ヘッダーを 32bit 境界に置くために IP 以降のデータをコピーする
             */
            iplen = ntohl(plist_current->php->reclen) - sizeof(struct snoop_pheader) - sizeof(struct ether_header);
            memmove(ether, ether + 1, iplen);
            ip = (struct ip *)ether;

            /* TCP の packet だけ読む */
            if( ip->ip_p == IPPROTO_TCP){
                /* tcp ヘッダのアドレスを計算。IP ヘッダのアドレスに ip_hl x 4 byte を足す */ 	
                tcphdr = (struct tcphdr *)((unsigned char *)ip + ((ip->ip_hl)<<2));
                if(optflag & VERBOSE){ /* 冗長出力用 */ 
                    printf("==========================================\n");
                    printf("Packet:%d, Len:%d \n",plist_current->packet_number, plist_current->packet_len);
                    printf("version     : %d\n",ip->ip_v);
                    printf("header len  : %d\n",ip->ip_hl);
                    printf("protocol    : %d\n",ip->ip_p);
                    printf("id          : %d\n",ntohs(ip->ip_id));
                    printf("check       : %x\n",ntohs(ip->ip_sum));
                    printf("saddr       : %s\n", inet_ntoa(ip->ip_src));
                    printf("daddr       : %s\n", inet_ntoa(ip->ip_dst));
                    printf("src port    : %hu\n", ntohs(tcphdr->th_sport));
                    printf("dst port    : %hu\n", ntohs(tcphdr->th_dport));
                    printf("seq         : %u\n", ntohl(tcphdr->th_seq));                    
                    printf("ack         : %u\n", ntohl(tcphdr->th_ack));                    
                    printf("win         : %hu\n", ntohs(tcphdr->th_win));

                    p = (unsigned char *)ip;
                    printf(" ");                    
                    for(j = 0 ; j < iplen ; j++){
                        printf("%02x", p[j]);
                        if((j+1)%16==0)
                            printf("\n");
                        if(j%2)
                            printf(" ");                    
                    }
                    printf("\n");                    
                }
                check_tcp_header(ip, tcphdr, plist_current);	
            }/* if proto == TCP */ 
            
            /* UDP の packet だけ読む */
            if( ip->ip_p == IPPROTO_UDP){
                /* UDP ヘッダのアドレスを計算。IP ヘッダのアドレスに ip_hl x 4 byte を足す */ 	
                udphdr = (struct udphdr *)((char *)ip + ((ip->ip_hl)<<2));
                check_udp_header(ip, udphdr, plist_current);	
            }/* if proto == UDP */

        } /* if ethertype == ethernet */
        plist_current++;
    }/* for() loop */
}

int
read_conn_list()
{
    connection_t *conn;
    int cnt = 0;

    /*
     * conn_head は空なので、次から・・
     */
    conn = conn_head->conn_next ;
    if(conn == NULL )
        return(0);

    printf("\n====================================\n");
    printf("        Connection List              \n");
    for(; conn != NULL ; conn = conn->conn_next ){
        printf("====================================\n");
        printf("addr 0: %s : Port: %hu\n",inet_ntoa(conn->addr0),conn->port0);
        printf("addr 1: %s : Port: %hu\n",inet_ntoa(conn->addr1),conn->port1);	        
        printf("Number of packets  : %d\n", conn->conn_count);
        cnt++;
    }
    printf("\nNumber of connections : %d\n", cnt);
    return(0);
}

int
read_pair_list()
{
	struct udp_port_pair_t *pair;

	/* pair_head は空なので、次から・・*/
	pair = pair_head->pair_next ;
	if(pair == NULL )
		return(0);

	printf("\n====================================\n");
	printf("        UPD port pair List              \n");
	for(; pair != NULL ; pair = pair->pair_next ){
		printf("====================================\n");
                printf("addr 0: %s : Port: %hu\n",inet_ntoa(pair->addr0),pair->port0);
                printf("addr 1: %s : Port: %hu\n",inet_ntoa(pair->addr1),pair->port1);
		printf("Number of packets  : %d\n", pair->pair_count);
	}
}

/*
 * tcp のデータ部より binary file を作る
 */ 
int
mkbin()
{ 
    connection_t *conn;
    stream_t *streams;
    double stream_init_time;  /* connection 毎の開始時間*/
    double receive_time;      /* 個々の packet の到着時間 */
    double previous_time = 0; /* 一つ前の packet の到着時間 */
    FILE *fp0;           /* direction 0 用の file pointer */
    FILE *fp1;           /* direction 1 用の file pointer */
    char file0[30];      /* direction 0 用の file 名 */
    char file1[30];      /* direction 1 用の file 名 */
    char tcpdata0[1514]; /* direction 0 用の data buffer */
    char tcpdata1[1514]; /* direction 1 用の data buffer */
    int tcpdatalen0;     /* direction 0 用 tcp data の length*/
    int tcpdatalen1;     /* direction 1 用 tcp data の length*/
        
    /* conn_head は空なので、次から・・*/
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
        printf("Addr 0: %s : Port: %d\n", inet_ntoa(conn->addr0),conn->port0);
        printf("Addr 1: %s : Port: %d\n", inet_ntoa(conn->addr1),conn->port1);
        /* file 名をセット*/
        sprintf(file0,"%s-%s",inet_ntoa(conn->addr0), inet_ntoa(conn->addr1));
        sprintf(file1,"%s-%s",inet_ntoa(conn->addr1), inet_ntoa(conn->addr0));
        if (( fp0 = fopen(file0,"wb")) == NULL){
            perror("fopen");
        }
        if (( fp1 = fopen(file1,"wb")) == NULL){
            perror("fopen");
        }

        /* 以下 個々の packet の処理 */
        for( streams = conn->stream ; streams != NULL ; streams = streams->stream_next){
            bzero((char *)tcpdata0,sizeof(tcpdata0));
            bzero((char *)tcpdata1,sizeof(tcpdata1));

            if(streams->direction){
                /* まず、ip_len と ip_hl と th_off より、packet 中のデータ長を計算*/
                tcpdatalen1 = TCPLEN(streams);
                /* TCP header の address + header len の address のデータ を一時 buffer に copy */
                memcpy(tcpdata1, (char *)streams->tcphdr + (streams->tcphdr->th_off<<2), tcpdatalen1 );
                /* ファイルに書き込み */
                fwrite(tcpdata1,sizeof(char), tcpdatalen1, fp1 );
            } else {
                tcpdatalen0 = TCPLEN(streams);
                memcpy(tcpdata0, (char *)streams->tcphdr + (streams->tcphdr->th_off<<2) ,tcpdatalen0 );
                fwrite(tcpdata0,sizeof(char), tcpdatalen0, fp0 );
            }
        }
        fclose(fp0);
        fclose(fp1);
    }
}

/*
 * connection リスト各パケットを表示。
 * オプションフラグによっては通常出力に加えて、
 * sequence 番号チェックを表示
 */
int
view_conn()
{ 
    connection_t *conn;
    stream_t *streams;
    stream_t *streams_check;
    uint32_t exp_ack; /* packet が期待する ACK 値 */
    uint32_t self_seq; /* Sefl packet SEQ 値 */
    uint32_t len; /* TCP の data の長さ*/
    double stream_init_time; /* connection 毎の開始時間*/
    double receive_time; /* 個々の packet の到着時間 */
    double previous_time = 0; /* 一つ前の packet の到着時間 */
    double acked_elapse ; /* ack を受けるまでの時間 */
    uint32_t next_seq[2];   /* Diag 用の 一つ前のパケットまでの SEQ の進行状況 */
    
    /* conn_head は空なので、次から・・*/
    conn = conn_head->conn_next ;
    if(conn == NULL )
        return(0);

    printf("\n====================================\n");
    printf("        Check each connection                \n");
    printf("====================================\n");
    for( ; conn != NULL ; conn = conn->conn_next) {
        printf("\n====================================\n");
        printf("Number of packets  : %d\n\n", conn->conn_count);
        printf("Addr 0: %s : Port: %d",inet_ntoa(conn->addr0),conn->port0);	
        printf("\t\t\t\t\t");
        printf("Addr 1: %s : Port: %d\n",inet_ntoa(conn->addr1),conn->port1);	        
        printf("---------------------------------------------------------------");
        printf("----------------------------------------------------------------\n");
        stream_init_time = TIMEVAL_TO_SEC(conn->stream->plist->php->pktime);
        previous_time = stream_init_time;

        /*
         * 以下 個々の packet の処理
         */
        for(streams = conn->stream ; streams != NULL ; streams = streams->stream_next ){
            receive_time = TIMEVAL_TO_SEC(streams->plist->php->pktime);
            INDENT(streams);
            /*
             * 以下 summary 表示部
             */
            printf("%d: ",streams->plist->packet_number);
            printf("%5.3f ",receive_time - previous_time);
            if (ntohs(streams->ip->ip_off) & (8191)){
                /*
                 * fragment offset が 0 以外（fragmentしていて、TCP header が無い) IP data gram を判定
                 */
                printf(" IP fragment");
                printf(" IPID: %u",ntohs(streams->ip->ip_id));
                printf(" Len:%4d", IPLEN(streams));                
                printf(" Flag: 0x%x",ntohs(streams->ip->ip_off));
                printf(" Offset: %u",((ntohs(streams->ip->ip_off)) & (8191))<<3);
                if (ntohs(streams->ip->ip_off) & IP_MF)
                    printf(" MF");
                if (ntohs(streams->ip->ip_off) & IP_DF)
                    printf(" DF");
                printf("\n");
            } else {
                /*
                 * IP fragment していない、もしくは最初の fragment の tcp packet
                 */
                printf("%u",  SEQ(streams));            
                printf("(%u)", ACK(streams));            
                printf(" Win:%d", ntohs(streams->tcphdr->th_win));
                printf(" Len:%u", TCPLEN(streams));
                if (ntohs(streams->ip->ip_off) & IP_MF)
                    printf(" MF");
                if (ntohs(streams->ip->ip_off) & IP_DF)
                    printf(" DF");                                            
                printf(" ");
                if(streams->tcphdr->th_flags & TH_FIN)
                    printf("FIN ");
                if(streams->tcphdr->th_flags & TH_SYN)
                    printf("SYN ");
                if(streams->tcphdr->th_flags & TH_RST)
                    printf("RST ");
                if(streams->tcphdr->th_flags & TH_PUSH)
                    printf("PSH ");
                if(streams->tcphdr->th_flags & TH_ACK)
                    printf("ACK ");
                if(streams->tcphdr->th_flags & TH_URG)
                    printf("URG ");
                printf("\n");
            }
            previous_time = receive_time ;            
                //printf("\t\t%s\n",streams->direction ? "<------------------\n" : "------------------>\n");

            
            if(!(optflag & DIAG))
                continue;
            
            /************** ここからは DIAG フラグがついていた場合だけ ******************/

            /*
             * more fragmen が立っている packet は ack の調査をしない                            
             * なぜなら、fragment の途中では　TCP segment としての total length がわからないので
             */
            if (ntohs(streams->ip->ip_off) & IP_MF){
                //INDENT(streams);
                //printf("\t> IP fragment packet.(can't check ack packet)\n");
                continue;
            }
            
            self_seq = SEQ(streams);
            /*
             * len は fragmen/non-fragment パケット双方の データ長が入る
             */
            len = TCPLEN(streams);

            /*
             * SACK(Selective Ack) Option の確認
             * TCP ヘッダー長が 5(=20bytes) より大きければ、なんらかの
             * TCP Option が設定されている
             */
            if(streams->tcphdr->th_off > 5 ){
                    uint16_t tcphdrlen;
                    char *tcpopt, *tcpopt_head;
                    uint8_t optlen;
                    struct sackval 
                    {
                        uint32_t leftedge;
                        uint32_t rightedge;
                    } *sackval;

                    tcphdrlen = streams->tcphdr->th_off <<2;
                    
                    tcpopt_head = tcpopt = (char *)streams->tcphdr + 20 ; 
                    while(*tcpopt != 0 && (tcpopt - tcpopt_head) < tcphdrlen - 20){
                        switch(*tcpopt){
                            case 1: /* NOP。次のoption へ*/
                                tcpopt++; 
                                if(optflag & VERBOSE) { INDENT(streams); printf("\t> NOP option found\n");}
                                break;
                            case 4: /* SACK Permitted option */
                                tcpopt = tcpopt + 2; /* SACK OK option 次の option へ */
                                INDENT(streams);                                                                
                                printf("\t> sack-permitted option found\n");
                                break;                                
                            case 5: /* SACK OPTION */{
                                int i;
                                char *pointer; /* 処理用のポインタ */

                                pointer = tcpopt + 1 + 1; /* type と lenght の分を進める*/
                                optlen = *(uint8_t *)(tcpopt + 1);
                                sackval = malloc(sizeof(struct sackval));

                                /*
                                 * Left edge と Right edige のペア(8bytes)が繋がっている。
                                 * optlen -2 / 8 回分だけループ
                                 */
                                for ( i = optlen - 2 ; i > 0 ; i = i - 8){
                                    memcpy(sackval, pointer, 8);
                                    INDENT(streams);                                
                                    printf("\t> sack = %u - %u\n", sackval->leftedge, sackval->rightedge);
                                    pointer = pointer + 8;
                                }
                                tcpopt = tcpopt + optlen;
                                free(sackval); /* もう使わないので free */
                                break;
                            }
                            default : /* 他の Option */
                                if(optflag & VERBOSE){ INDENT(streams); printf("\t> TCP option found\n");}
                                optlen = *(uint8_t *)(tcpopt + 1); 
                                tcpopt = tcpopt + optlen; 
                                break;
                        } /* switch end */
                    } /* while end */
                } /* if tcphdr > 20 end */
            
            /*
             * 次にくると期待されていた SEQ と、このパケットの SEQ を比較
             * もし、期待値よりも大きければ、順番が入れ替わったか、または
             * パケットのドロップの可能性がある
             */
            if(conn->snd_nxt[streams->direction] == 0){
                    /* 期待する SEQ(SND_NXT)が 0 つまりここは snoop でのこの TCP */
                    /* connction の最初の packet だけが該当する                  */
                conn->snd_nxt[streams->direction] = SEQ(streams) + len + SYNFIN(streams->tcphdr);
            } else {
                next_seq[streams->direction] = conn->snd_nxt[streams->direction];
                if( next_seq[streams->direction] < SEQ(streams))
                {
                    /* 期待しているより、大きい SEQ 番号がきた */
                    INDENT(streams);
                    printf("\t> out of order data packet. expected SEQ = %u\n",next_seq[streams->direction]);
                    
                }
                else if (next_seq[streams->direction] == SEQ(streams)){
                    /* 期待通りのパケットが来た。snd_nxt を更新                       */
                    conn->snd_nxt[streams->direction] = SEQ(streams) + len + SYNFIN(streams->tcphdr);
                }
                else{
                        /* 期待値よりも小さい SEQ。再送？*/

                    INDENT(streams);
                    printf("\t> retransmission packet?\n");
                }

                /*
                 * これより前の packet に SND_NXT の SEQ が含まれているか調べる & 再送のチェック
                 * TODO:ここはデータがある全 packet が通るため、大変負荷が高い。要改善
                 */
                if( len > 0){
                    for(streams_check =  conn->stream ; streams_check != streams ; streams_check = streams_check->stream_next){
                         /* Self packet のみをチェック*/
                        if (streams_check->direction != streams->direction) 
                            continue;
                        /* last fragment(IP_MF の立ってない)パケットのみをチェック */
                        if (ntohs(streams_check->ip->ip_off) & IP_MF) 
                            continue;

                        /* データがあって、SEQ と SND_NXT が同じ packet を調べる*/	
                        if ( TCPLEN(streams_check) > 0 && SEQ(streams_check) == conn->snd_nxt[streams->direction]){
                            conn->snd_nxt[streams->direction] =
                                SEQ(streams_check) + TCPLEN(streams_check)  + SYNFIN(streams_check->tcphdr);
                            INDENT(streams);
                            printf("\t> SEQ = %u was already sent by pakcet %d\n",
                                   SEQ(streams_check), streams_check->plist->packet_number);
                                /* まだ、他にもあるかもしれないので、最初から調べ直す。*/
                            streams_check = conn->stream;
                            continue;
                        }
                        /* SEQ が同じで、データを持っている packet を調べる*/	
                        if( (SEQ(streams_check) == self_seq) && (TCPLEN(streams_check) != 0)){
                            INDENT(streams);
                            printf("\t> may retransmission packet of packet%d\n",streams_check->plist->packet_number);
                        }
                    } /* 以前の packet のチェックのループ終わり*/
                } /* もしデータがあったら・・*/
                
            }/* if SND_NXT == 0 else .. end */

            
            if(streams->stream_next == NULL){ /* つぎの packet が無い*/
                INDENT(streams);
                printf("\t> ...won't check ack packet. No more packets\n");
                continue;
            }            

            /*
             * まず、ACK が必要かどうか（データ有り、または FIN or SYN)を確認 
             * 必要無ければ、他の packet を調べない。必要なら次の for() ループへ
             */
            if(len != 0){
                /*
                 * データがある場合
                 */
                exp_ack = SEQ(streams) + len ;
                if(SYNFIN(streams->tcphdr)){
                    /*
                     * FIN or SYN の場合
                     */
                    exp_ack++;
                }
                INDENT(streams);                
                printf("\t> expecting ACk = %u\n",exp_ack);
            } else {
                /*
                 * データがない場合
                 */                
                if(SYNFIN(streams->tcphdr)){
                    /*
                     * FIN or SYN の場合
                     */
                    exp_ack = SEQ(streams) + 1;
                    INDENT(streams);
                    printf("\t> expecting ACK = %u\n",exp_ack);
                } else {
                    /*
                     * ただの ACK パケット。
                     * なので、以下のACK のチェックも、再送のチェックも行わない
                     */
                    INDENT(streams);
                    printf("\t> doesn't expect to be acked\n");
                    continue;
                }
            }

            /*
             * これより後の packet から期待する ACK があるかどうかをチェック
             */
            for(streams_check = streams->stream_next ; streams_check != NULL ; streams_check = streams_check->stream_next){
                if (streams_check->direction == streams->direction){ /* 相手からの packet のみをチェック*/
                    if(streams_check->stream_next == NULL){ /* もしこれが最後の packet なら ACK されていないと言うこと*/
                        INDENT(streams);                        
                        printf("\t> not acked!!!\n");
                    }
                    continue;
                }

                /* 相手からの packet の fragment の有無をチェックする必要は無い。*/
                /* 期待する ack をもつ packet を調べる*/	
                if( ACK(streams_check) == exp_ack ){
                    acked_elapse = TIMEVAL_TO_SEC(streams_check->plist->php->pktime);
                    INDENT(streams);
                    printf("\t> exactly acked by %d(%f Sec)\n",
                           streams_check->plist->packet_number, acked_elapse - receive_time);
                    break;
                } else if (ACK(streams_check) > exp_ack ){
                    acked_elapse = TIMEVAL_TO_SEC(streams_check->plist->php->pktime);
                    INDENT(streams);
                    printf("\t> acked by %d(%f Sec)\n",
                           streams_check->plist->packet_number,acked_elapse - receive_time);
                    break;
                }

                if(streams_check->stream_next == NULL){ /* 最後まで来たら ACK されていないと言うこと*/
                    INDENT(streams);
                    printf("\t> not acked!!!\n");
                }
            } /* loop for searching ack end */
        } /* loop for stream end */
    } /* loop for connection list end */
}


/* UDP port pair リスト各パケットを表示。*/
int
view_pair()
{ 
    struct udp_port_pair_t *pair;
    struct udp_stream_t *udp_streams;
    struct udp_stream_t *udp_streams_check;
    double udp_stream_init_time; /* UDP port pair 毎の開始時間*/
    double receive_time; /* 個々の packet の到着時間 */
    double previous_time = 0; /* 一つ前の packet の到着時間 */
    

        /* pair_head は空なので、次から・・*/
    pair = pair_head->pair_next ;
    if(pair == NULL )
        return(0);


    printf("\n====================================\n");
    printf("        Check each UDP port pair                \n");
    printf("====================================\n");
    for( ; pair != NULL ; pair = pair->pair_next) {
        printf("\n====================================\n");
        printf("Number of packets  : %d\n\n", pair->pair_count);
        printf("Addr 0: %s : Port: %d",inet_ntoa(pair->addr0), pair->port0);
        printf("\t\t\t\t\t");
        printf("Addr 1: %s : Port: %d",inet_ntoa(pair->addr1), pair->port1);        
        printf("---------------------------------------------------------------");
        printf("----------------------------------------------------------------\n");
        udp_stream_init_time = TIMEVAL_TO_SEC(pair->udp_stream->plist->php->pktime);
        previous_time = udp_stream_init_time;

            /* 以下 個々の packet の処理 */
        for(udp_streams = pair->udp_stream ; udp_streams != NULL ; udp_streams = udp_streams->udp_stream_next ){

            receive_time = TIMEVAL_TO_SEC(udp_streams->plist->php->pktime);

            INDENT(udp_streams);
            
                /* 以下 summary 表示部 */
            printf("%d: ",udp_streams->plist->packet_number);
            printf("%5.3f ",receive_time - previous_time);
            printf(" IPID: %u",ntohs(udp_streams->ip->ip_id));
            printf(" Len:%4d", UDPLEN(udp_streams));
            printf("  ");
            printf(" Flag: 0x%x",ntohs(udp_streams->ip->ip_off));
            printf(" Offset: %u",((ntohs(udp_streams->ip->ip_off)) & (8191))<<3);
            if (ntohs(udp_streams->ip->ip_off) & IP_MF)
                printf(" MF");
            if (ntohs(udp_streams->ip->ip_off) & IP_DF)
                printf(" DF");                                

            previous_time = receive_time ;
            printf("\n");
            
            if(!(optflag & DIAG))
                continue;
				
        } /* loop for udp_stream end */
    } /* loop for UDP port pair list end */
}

/*
 * ether header の type フィールドを読んで、type を識別。
 * IP の時だけ 1 を返す
 * また、802.3 フレームの場合は・・・別処理へ（未実装）
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

void
print_usage(char *name)
{
    printf("Usage: %s [ -ldv ] <file name> \n",name); 
    printf("             -l : view connections list\n"); 
    printf("             -d : view packet with Seq+Ack diagnosis\n"); 
    printf("             -v : view packet \n");
    printf("             -b : make tcp data files\n");
    printf("             -u : view UDP packet\n");
    printf("             -D : print verbose output\n");
    printf("\n");
    printf("Example:\n");
    printf("  snoopdiag -ldD snoop.out\n");
}
