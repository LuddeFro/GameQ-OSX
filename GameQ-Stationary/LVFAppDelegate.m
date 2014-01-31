//
//  LVFAppDelegate.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 10/24/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFAppDelegate.h"

#define kNOGAME 0
#define kHEROES_OF_NEWERTH 1
#define kDOTA2 2
#define kCS_GO 3
#define REGISTER_URL @"https://www.gameq.com/register"
#define kOFFLINE 0 //app running, but no game
#define kONLINE 1 //game running
#define kINGAME 2 //game running and in match

#define kNUMBER_OF_GAMES 4 //kNOGAME counts as 1


void * reftoself;

@implementation LVFAppDelegate

@synthesize persistentStoreCoordinator = _persistentStoreCoordinator;
@synthesize managedObjectModel = _managedObjectModel;
@synthesize managedObjectContext = _managedObjectContext;





@synthesize mainMenu;
@synthesize statusBar;
@synthesize countdownQuickTimer;
@synthesize countdownSlowTimer;
@synthesize honQPack;
@synthesize dotaQPack;
@synthesize dotaCPack;
@synthesize csgoQPack;
@synthesize bolFirstTick;
@synthesize bolInGameArray;
@synthesize bolOnlineArray;
@synthesize btnLog;
@synthesize btnQuitApp;
@synthesize btnToggleActive;
@synthesize bolLoggedIn;
@synthesize loginWindow;
@synthesize txtEmail;
@synthesize txtPassword;
@synthesize btnSignUp;
@synthesize btnLogin;
@synthesize bolIsActive;
@synthesize dotaQBuffer;





/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 50

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr *ip_src,*ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};


struct sniff_udp {
    u_short uh_sport;               /* source port */
    u_short uh_dport;               /* destination port */
    u_short uh_ulen;                /* udp length */
    u_short uh_sum;                 /* udp checksum */
    
};

#define SIZE_UDP        8               /* length of UDP header */
// total udp header length: 8 bytes (=64 bits)



pcap_t *handle;		/* Session handle */

//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------



//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------

const char *dev;		/* Device to sniff on */
char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
struct bpf_program fp;		/* The compiled filter expression */
char filter_exp[] = "udp dst portrange 11235-11335 or tcp dst port 11031 or udp src portrange 27015-27030 or udp dst port 27005";	/* The filter expression */
bpf_u_int32 mask;		/* The netmask of our sniffing device */
bpf_u_int32 net;		/* The IP of our sniffing device */
//  struct pcap_pkthdr header;	/* The header that pcap gives us */
//  const u_char *packet;		/* The actual packet */
int num_packets = 0; /* the number of packets to be caught*/


//manages mouseover event for registration button
- (void)mouseEntered:(NSEvent *)theEvent
{
    NSColor *color = [NSColor blueColor];
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:btnSignUp.attributedTitle];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:color range:titleRange];
    [btnSignUp setAttributedTitle: colorTitle];
}
//manages mouseover events ending for registration button
- (void)mouseExited:(NSEvent *)theEvent
{
    NSColor *color = [NSColor blackColor];
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:btnSignUp.attributedTitle];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:color range:titleRange];
    [btnSignUp setAttributedTitle: colorTitle];
}

// a login attempt is made
- (void)attemptLogin
{
    //checks if any text exists in the fields
    if (![txtEmail.stringValue isEqual:@""] && ![txtPassword.stringValue isEqual:@""]) {
        [_connectionsHandler loginWithUser:txtEmail.stringValue andPass:txtPassword.stringValue];
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter a valid email address and password"] runModal];
    }
    
}
// pressed button that they dont have an account, link them to signup page!
-(void)goToRegistration
{
    NSURL *registerURL = [[NSURL alloc] initWithString:REGISTER_URL];
    [[NSWorkspace sharedWorkspace] openURL:registerURL];
}

- (void)application:(NSApplication*)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData*)deviceToken
{
    
	NSLog(@"My token is: %@", deviceToken);
    
    LVFDataModel *dataHandler = [[LVFDataModel alloc] initWithAppDelegate:self];
    NSString *oldToken = [dataHandler getToken];
	NSString *newToken = [deviceToken description];
	newToken = [newToken stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
	newToken = [newToken stringByReplacingOccurrencesOfString:@" " withString:@""];
    
	NSLog(@"My token is: %@", newToken);
    [dataHandler setToken:newToken];
	if ([dataHandler getBolIsLoggedIn] && ![newToken isEqualToString:oldToken])
	{
		LVFConnect *connectHandler = [[LVFConnect alloc] init];
        [connectHandler postNow:[NSString stringWithFormat:@"token=%@&device=%@", newToken, [dataHandler getDeviceID]] to:updateTokenURL];
	}
}




- (void)application:(NSApplication*)application didFailToRegisterForRemoteNotificationsWithError:(NSError*)error
{
	NSLog(@"Failed to get token, error: %@", error);
}


- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    
    
    
    //first init
    _dataHandler = [[LVFDataModel alloc] initWithAppDelegate:self];
    NSLog(@"%@", [_dataHandler getDeviceID]);
    if ([_dataHandler getDeviceID] == NULL) {
        [_dataHandler setDeviceID: [[NSHost currentHost] localizedName]];
    }
    NSLog(@"%@", [_dataHandler getDeviceID]);
    
    
    
    //initailizing state
    [[NSApplication sharedApplication] registerForRemoteNotificationTypes:(NSRemoteNotificationTypeAlert | NSRemoteNotificationTypeBadge | NSRemoteNotificationTypeSound)];
    _connectionsHandler = [[LVFConnections alloc] init];
    _windowHandler = [[LVFWindowHandler alloc] init];
    bolIsActive = false;
    bolFirstTick = true;
    bolInGameArray = [[NSMutableArray alloc] init];
    bolOnlineArray = [[NSMutableArray alloc] init];
    for (int j = 0; j<kNUMBER_OF_GAMES ; j++) {
        [bolInGameArray insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [bolOnlineArray insertObject:[NSNumber numberWithBool:NO] atIndex:j];
    }
    if ([_dataHandler getBolIsLoggedIn]) {
        [_connectionsHandler loginWithUser:[_dataHandler getEmail] andPass:[_dataHandler getPass]];
    }
    NSLog(@"stored data:\r\nloggedin: %@\r\nemail: %@\r\ntoken: %@\r\npassword: like I would tell you :P \r\ndeviceID:%@", [_dataHandler getBolIsLoggedIn], [_dataHandler getEmail], [_dataHandler getToken], [_dataHandler getDeviceID]);
    
    
    
    //pCap vars
    struct ifaddrs* interfaces = NULL;
    struct ifaddrs* temp_addr = NULL;
    
    
    
    // creating statusbar item
    self.statusBar = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    
    NSColor *color = [NSColor colorWithCalibratedRed:0 green:0 blue:0 alpha:1];
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithString:self.statusBar.title];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:color range:titleRange];
    [self.statusBar setAttributedTitle: colorTitle];
    self.statusBar.image = [NSImage imageNamed:@"Qblack.png"];
    [self.statusBar setHighlightMode:YES];
    [self.statusBar setAlternateImage:[NSImage imageNamed:@"Qwhite.png"]];
    self.statusBar.menu = self.mainMenu;
    self.statusBar.highlightMode = TRUE;
    [NSApp setActivationPolicy:NSApplicationActivationPolicyProhibited];
    
    
    dotaQBuffer = [[LVFBuffer alloc] init];
    NSLog(@"init delegate");
    
    
    
    
    
    
    
    //setup the login window
    NSRect winFrame = NSRectFromCGRect(CGRectMake(0, 0, 373, 173));
    NSUInteger stylemask = NSTexturedBackgroundWindowMask|NSClosableWindowMask|NSMiniaturizableWindowMask|NSTitledWindowMask|NSResizableWindowMask;
    loginWindow = [[NSWindow alloc] initWithContentRect:winFrame styleMask:stylemask backing:NSBackingStoreBuffered defer:YES];
    [loginWindow setReleasedWhenClosed:NO];
    [loginWindow center];
    NSRect mailFrame = NSRectFromCGRect(CGRectMake(78, 105, 217, 25));
    NSRect passFrame = NSRectFromCGRect(CGRectMake(78, 75, 217, 25));
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(136.5, 40, 100, 25));
    NSRect regFrame = NSRectFromCGRect(CGRectMake(136.5, 12, 100, 25));
    
    NSRect firstNameFrame = NSRectFromCGRect(CGRectMake(78, 195, 217, 25));
    NSRect lastNameFrame = NSRectFromCGRect(CGRectMake(78, 165, 217, 25));
    NSRect yobFrame = NSRectFromCGRect(CGRectMake(78, 135, 217, 25));
    NSRect genderFrame = NSRectFromCGRect(CGRectMake(149.5, 55, 140, 60));
    NSRect countryFrame = NSRectFromCGRect(CGRectMake(136.5, 105, 100, 25));
    
    txtPassword = [[NSSecureTextField alloc] initWithFrame:passFrame];
    txtEmail = [[NSTextField alloc] initWithFrame:mailFrame];
    btnSignUp = [[NSButton alloc] initWithFrame:regFrame];
    btnLogin = [[NSButton alloc] initWithFrame:loginFrame];
    [[txtPassword cell] setPlaceholderString:@"Password"];
    [[txtEmail cell] setPlaceholderString:@"E-Mail"];
    [btnLogin setTitle:@"Log In"];
    [btnSignUp setTitle:@"Register"];
    [btnLogin setBezelStyle:NSRoundedBezelStyle];
    [btnLogin setTarget:self];
    [btnLogin setAction:@selector(attemptLogin)];
    [btnSignUp setTarget:self];
    [btnSignUp setAction:@selector(goToRegistration)];
    [btnSignUp setButtonType:NSMomentaryLight];
    [btnLogin setButtonType:NSMomentaryLight];
    [btnSignUp setBordered:YES];
    [btnSignUp setBezelStyle:NSRoundedBezelStyle];
    [btnLogin setBordered:YES];
    
    _txtFirstName = [[NSTextField alloc] initWithFrame:firstNameFrame];
    _txtLastName = [[NSTextField alloc] initWithFrame:lastNameFrame];
    _txtYOB = [[NSTextField alloc] initWithFrame:yobFrame];
    _rolloverCountry = [[NSPopUpButton alloc] initWithFrame:countryFrame pullsDown:YES];
    _segSex = [[NSSegmentedControl alloc] initWithFrame:genderFrame];
    
    [_segSex setSegmentCount:2];
    [_segSex setImage:[NSImage imageNamed:@"i5woman.png"] forSegment:0];
    [_segSex setImage:[NSImage imageNamed:@"i5man.png"] forSegment:1];
    [_segSex setSegmentStyle:NSSegmentStyleCapsule];
    
    [[_txtYOB cell] setPlaceholderString:@"Year of Birth"];
    [[_txtFirstName cell] setPlaceholderString:@"First Name"];
    [[_txtLastName cell] setPlaceholderString:@"Last Name"];
    
    
    [loginWindow.contentView addSubview:_txtFirstName];
    [loginWindow.contentView addSubview:_txtLastName];
    [loginWindow.contentView addSubview:_txtYOB];
    [loginWindow.contentView addSubview:_segSex];
    [loginWindow.contentView addSubview:_rolloverCountry];
    [loginWindow.contentView addSubview:txtPassword];
    [loginWindow.contentView addSubview:txtEmail];
    [loginWindow.contentView addSubview:btnSignUp];
    [loginWindow.contentView addSubview:btnLogin];
    [[loginWindow contentView] setAutoresizesSubviews:YES];
    [btnLogin setKeyEquivalent:@"\r"];
    [loginWindow setDelegate:_windowHandler];
    
    
    
    
    
    
    
    // define the device!
    
    // retrieve the current interfaces - returns 0 on success
    NSInteger success = getifaddrs(&interfaces);
    if (success == 0)
    {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while (temp_addr != NULL)
        {
            if (temp_addr->ifa_addr->sa_family == AF_INET) // internetwork only
            {
                NSString* name = [NSString stringWithUTF8String:temp_addr->ifa_name];
                NSString* address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
                NSLog(@"interface name: %@; address: %@", name, address);
                
                //check for loopback address
                if (![[address substringToIndex:3] isEqualToString:@"127"]) {
                    dev = [name UTF8String];
                }
            }
            
            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);
    
    printf("Device: %s\n", dev);
    
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        fprintf(stderr, "Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
    }
    
    /* Open the session*/
    handle = pcap_open_live(dev, SNAP_LEN, 0, 100, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return;
    }
    /* Compile a filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1){
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    /* Apply a filter */
    if (pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }
    
}

    
-(void) setupRegister{
    NSRect winFrame = NSRectFromCGRect(CGRectMake(0, 0, 373, 343));
    NSRect mailFrame = NSRectFromCGRect(CGRectMake(78, 255, 217, 25));
    NSRect passFrame = NSRectFromCGRect(CGRectMake(78, 225, 217, 25));
    NSRect firstNameFrame = NSRectFromCGRect(CGRectMake(78, 195, 217, 25));
    NSRect lastNameFrame = NSRectFromCGRect(CGRectMake(78, 165, 217, 25));
    NSRect yobFrame = NSRectFromCGRect(CGRectMake(78, 135, 217, 25));
    NSRect genderFrame = NSRectFromCGRect(CGRectMake(149.5, 55, 140, 60));
    NSRect countryFrame = NSRectFromCGRect(CGRectMake(136.5, 105, 100, 25));
    
    [loginWindow setFrame:winFrame display:YES];
    [txtEmail setFrame:mailFrame];
    [txtPassword setFrame:passFrame];
    [_txtFirstName setFrame:firstNameFrame];
    [_txtLastName setFrame:lastNameFrame];
    [_txtYOB setFrame:yobFrame];
    [_segSex setFrame:genderFrame];
    [_rolloverCountry setFrame:countryFrame];
    
    
    
}

-(void) setupLogin{
    
}


static void got_packet(id self, const struct pcap_pkthdr *header,
                       const u_char *packet)
{
    
    
	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
    //  const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
    const struct sniff_udp *udp;
	u_char *payload;                    /* Packet payload */
    
    /* UDP header */
    
    
    
    
    
    
    
	int size_ip;
	int size_tcp;
    int size_udp;
    int size_payload;
	
	printf("\nPacket number %d:\n", count);
	count++;
	
	/* define ethernet header */
    //	ethernet = (struct sniff_ethernet*)(packet);
	
	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
    
	/* print source and destination IP addresses */
    //	printf("       From: %s\n", inet_ntoa(ip->ip_src));
    //	printf("         To: %s\n", inet_ntoa(ip->ip_dst));
	
	/* determine protocol */
	switch(ip->ip_p) {
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
            // what happens if it's UDP
            //--
            
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            size_udp = ntohs(udp->uh_ulen);
            
            if (size_udp < 8) {
                printf("   * Invalid UDP header length: %u bytes\n", size_udp);
            }
            printf("Header length: %u bytes\n", size_udp);
            
            
            printf("   Src port: %d\n", ntohs(udp->uh_sport));
            printf("   Dst port: %d\n", ntohs(udp->uh_dport));
        
        
            
            int dport = ntohs(udp->uh_dport);
            int sport = ntohs(udp->uh_sport);
            if (dport <= 11335 && dport >= 11235) {
                
                NSLog(@"Hon Packet");
                [self incrementHonQPack];
                NSLog(@"%d",[self honQPack]);
            }
            
            if (sport >= 27015 && sport <= 27019 && ntohs(ip->ip_len) <= 686 && ntohs(ip->ip_len) >= 586) {
                NSLog(@"Dota Q Packet");
                [self incrementDotaQPack];
                NSLog(@"%d",[self dotaQPack]);
                
            }
            
            if (dport == 27005) {
                [self incrementDotaCPack];
                NSLog(@"Dota C Packet");
                NSLog(@"%d",[self dotaCPack]);
            }
            
            
            
            /*
             *  OK, this packet is UDP.
             */
            
            /* define/compute tcp header offset */
            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + SIZE_UDP);
            
            printf("   Src port: %d\n", ntohs(udp->uh_sport));
            printf("   Dst port: %d\n", ntohs(udp->uh_dport));
            
            /* define/compute udp payload (segment) offset */
            payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + SIZE_UDP);
            
            /* compute udp payload (segment) size */
            size_payload = ntohs(ip->ip_len) - (size_ip + SIZE_UDP);
            if (size_payload > ntohs(udp->uh_ulen))
                size_payload = ntohs(udp->uh_ulen);
            
            /*
             * Print payload data; it might be binary, so don't just
             * treat it as a string.
             */
            if (size_payload > 0) {
                printf("   Payload (%d bytes):\n", size_payload);
                print_payload(payload, size_payload);
            }
            
            
            
            
            
            
            
            
            
            //--
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}
	
	/*
	 *  OK, this packet is TCP.
	 */
	
	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}
    
    printf("Header length: %u bytes\n", size_tcp);
    
    /*
    int dport = ntohs(tcp->th_dport);
	
     //Hon chat server packets
     
     if (dport == 11031) {
        NSLog(@"Hon ChatPacket");
        [self incrementHonCPack];
        NSLog(@"%i",[self honCPack]);
        
        
    }*/
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    
    
    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{
    
	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;
    
	if (len <= 0)
		return;
    
	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}
    
	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}
    
    return;
}


/*
 * print data in rows of 16 bytes: offset   hex   ascii
 *
 * 00000   47 45 54 20 2f 20 48 54  54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..
 */
void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    
	int i;
	int gap;
	const u_char *ch;
    
	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}
    
	printf("\n");
    
    return;
}






















// toggle on/off the pCap----------------------------------
- (IBAction)toggle:(id)sender {
    if (!bolIsActive) {
        [NSThread detachNewThreadSelector:@selector(toggleOn:) toTarget:self withObject:nil];
    } else {
        [self toggleOff:nil];
    }
    NSLog(@"%@", [NSNumber numberWithBool:bolIsActive]);
    bolIsActive = !bolIsActive;
    NSLog(@"%@", [NSNumber numberWithBool:bolIsActive]);
    
}

- (IBAction)toggleOff:(id)sender {
    [_btnStatus2 setTitle:@"Status: Online"];
    pcap_breakloop(handle);
    printf("\nCapture complete.\n");
    [self performSelectorOnMainThread:@selector(stopTimer) withObject:nil waitUntilDone:false];
    bolFirstTick = true;
    [btnToggleActive setTitle:@"Start Monitoring"];
    printf("\nCapture complete.\n");
    NSColor *color = [NSColor colorWithCalibratedRed:0 green:0 blue:0 alpha:1];
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithString:@"GQ"];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:color range:titleRange];
    [self.statusBar setAttributedTitle: colorTitle];
    self.statusBar.image = [NSImage imageNamed:@"Qblack.png"];
    
}

- (IBAction)toggleOn:(id)sender {
    [_btnStatus2 setTitle:@"Status: Tracking"];
    NSColor *color = [NSColor colorWithCalibratedRed:0.1 green:0.3 blue:0.7 alpha:1];
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithString:@"GQ"];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:color range:titleRange];
    
    [self.statusBar setAttributedTitle: colorTitle];
    
    printf("\nCapture started.\n");
    [self performSelectorOnMainThread:@selector(startTimer) withObject:nil waitUntilDone:false];
    [btnToggleActive setTitle:@"Stop Monitoring"];
    printf("\nCapture started.\n");
    pcap_loop(handle, num_packets, got_packet, self);
    self.statusBar.image = [NSImage imageNamed:@"Qblue.png"];
}
// end toggle  ---------------------------------------------

- (void) startTimer {
    countdownQuickTimer = [NSTimer timerWithTimeInterval:1 target:self selector:@selector(tack:) userInfo:nil repeats:YES];
    [[NSRunLoop currentRunLoop] addTimer:countdownQuickTimer forMode:NSDefaultRunLoopMode];
    //countdownSlowTimer = [NSTimer timerWithTimeInterval:5 target:self selector:@selector(tick:) userInfo:nil repeats:YES];
    //[[NSRunLoop currentRunLoop] addTimer:countdownSlowTimer forMode:NSDefaultRunLoopMode];
}
- (void) stopTimer {
    [countdownQuickTimer invalidate];
    //[countdownSlowTimer invalidate];
}

// reg / login button is selected from the GQ toolbar menu
- (IBAction)log:(id)sender
{
    [btnToggleActive setEnabled:NO];
    if(bolLoggedIn) {
        [_connectionsHandler logoutPost];
        
    } else {
        [loginWindow close];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
        [self setupLogin];
        [loginWindow center];
        [loginWindow makeKeyAndOrderFront:self];
        NSLog(@"showing window");
        
        
    }
}
- (void)logIn
{
    
    
    
    [_connectionsHandler loginWithUser:txtEmail.stringValue andPass:txtPassword.stringValue];
    
}

- (void) setConnected
{
    
    
    [btnLog setTitle:@"Log Out"];
    [btnToggleActive setEnabled:true];
    // following tells the server the client is online but no games have been launched
    [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:kNOGAME] andStatus:[NSNumber numberWithInt:kOFFLINE]];
    bolLoggedIn = YES;
    [_dataHandler setBolIsLoggedIn:[NSNumber numberWithBool:YES]];
    [_dataHandler setEmail:[txtEmail stringValue]];
    NSLog(@"set email to %@", txtEmail.stringValue);
    NSLog(@"email is %@", [_dataHandler getEmail]);
    [_dataHandler setPass:[txtPassword stringValue]];
    [txtPassword setStringValue:@""];
    [_connectionsHandler.gqConnect postNow:[NSString stringWithFormat:@"token=%@&device=%@", [_dataHandler getToken], [_dataHandler getDeviceID]] to:updateTokenURL];
    NSLog(@"token posted");
    [loginWindow close];
    
    [_btnStatus setTitle:[NSString stringWithFormat:@"%@", [_dataHandler getEmail]]];
    [_btnStatus2 setTitle:@"Status: Online"];
    [_btnStatus setHidden:NO];
    [self toggle:nil];
    
    
}
- (void) setDisconnected
{
    bolLoggedIn = NO;
    [_dataHandler setBolIsLoggedIn:[NSNumber numberWithBool:NO]];
    [_dataHandler setPass:@""];
    [txtPassword setStringValue:@""];
    if (bolIsActive) {
        [self toggle:nil];
    }
    [self.btnLog setTitle:@"Log In"];
    [btnToggleActive setEnabled:NO];
    [_btnStatus setHidden:YES];
    [_btnStatus2 setTitle:@"Status: Offline"];
}






// quits the app
- (IBAction)quit:(id)sender {
    [self toggleOff:(nil)];
    pcap_freecode(&fp);
	pcap_close(handle);
    [NSApp terminate:self];
}

//what happens on tack? (quick timer)
- (IBAction)tack:(id)sender {
    NSLog(@"tick");
    // get processes
    NSString *output = [NSString string];
    for (NSRunningApplication *app in
         [[NSWorkspace sharedWorkspace] runningApplications]) {
        output = [output stringByAppendingFormat:@"%@\n",
                  [app localizedName] /*absoluteString*/];
    }
    
    //NSLog(@"%@", output);
    
    
    //NSLog(@"<<<processes checked>>>");
    
    //-------------------check processes------------------
    BOOL honRunning = false;
    BOOL dotaRunning = false;
    BOOL csgoRunning = false;
    if ([output rangeOfString:@"Heroes"].location == NSNotFound || [output rangeOfString:@"Newerth"].location == NSNotFound) {
        honRunning = false;
        //NSLog(@"hon not running, false alarm");
    } else {
        honRunning = true;
        //NSLog(@"hon running, probably true alarm");
    }
    if ([output rangeOfString:@"dota"].location == NSNotFound) {
        dotaRunning = false;
        //NSLog(@"dota not running, false alarm");
    } else {
        dotaRunning = true;
        //NSLog(@"dota running, probably true alarm");
    }
    if ([output rangeOfString:@"csgo"].location == NSNotFound) {
        csgoRunning = false;
        //NSLog(@"csgo not running, false alarm");
    } else {
        csgoRunning = true;
        //NSLog(@"csgo running, probably true alarm");
    }


    
    // ---------------- HON handler ----------------------
    
    if (honQPack > 1 && honRunning) {
        // user is in game
        [self inGame:kHEROES_OF_NEWERTH];
    } else if (honRunning){
        [self online:kHEROES_OF_NEWERTH];
        //got no packets but it's on
    } else {
        // user is not in game
        [self offline:kHEROES_OF_NEWERTH];
    }
    // -------------- HON handler end --------------------
    
    
    // ---------------- DOTA handler ----------------------
    [dotaQBuffer increment:dotaQPack];
    NSLog(@"buffer: %i", dotaQBuffer.bufferValue);
    NSLog(@"%i", dotaRunning);
    if (dotaQBuffer.bufferValue > 1 && dotaRunning) {
        [self inGame:kDOTA2]; //potentially sends notification
    }
    if (dotaCPack > 1 && dotaRunning) {
        // user is in game
        bolFirstTick = 1; //tricks the app in to not sending a notification
        [self inGame:kDOTA2];
    } else if (dotaRunning){
        [self online:kDOTA2];
        
    } else {
        // user is not in game
        [self offline:kDOTA2];
    }
    // -------------- DOTA handler end --------------------
    
    
    
    dotaCPack = 0;
    dotaQPack = 0;
    honQPack = 0;
    bolFirstTick = 0;
    //NSLog(@"");
}

// slow buffer timer
- (IBAction)tick:(id)sender {
    
}





// handles offline state
- (IBAction)offline:(int)game {
    
    NSLog(@"called method \"offline\"");
    if (![[bolOnlineArray objectAtIndex:game] boolValue]) {
        // do nothing if status already offline, (initialized to offline)
    } else {
        
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kOFFLINE]];
    }
    [bolOnlineArray insertObject:[NSNumber numberWithBool:NO] atIndex:game];
    
}

//called whenever online status is detected
- (IBAction)online:(int)game {
    
    NSLog(@"called method \"online\"");
    if ([[bolOnlineArray objectAtIndex:game] boolValue]) {
        // do nothing if status already online, (initialized to offline)
    } else {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kONLINE]];
    }
    [bolOnlineArray insertObject:[NSNumber numberWithBool:YES] atIndex:game];
}

//executes every quick timer user is in a match
- (IBAction)inGame:(int)game {
    NSLog(@"called method \"ingame\"");
    // if its the first tick
    if (bolFirstTick) {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kINGAME]];
        
    } else if(!bolFirstTick && [[bolInGameArray objectAtIndex:game] boolValue]){
        //do nothing
        
    } else if(!bolFirstTick && ![[bolInGameArray objectAtIndex:game] boolValue]) {
        [_connectionsHandler pushNotificationForGame:[NSNumber numberWithInt:game]];
    }
    [bolInGameArray insertObject:[NSNumber numberWithBool:YES] atIndex:game];
    
}


/* What the fuck does this method do? this was active while offline:(int)game was inactive.... it was wrong!?!?
//executes every quick timer user has not launched a game
- (IBAction)outGame:(int)game {
    if (bolFirstTick) {
        //do nothing, bolInGame initialized to false
        
    } else if(!bolFirstTick && bolInGame){
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kONLINE]];
        
    } else if(!bolFirstTick && !bolInGame) {
        //do nothing
    }
    bolInGame = 0;
}*/




//increment methods used to alter variables from within libPCap function "got_packet"
- (IBAction)incrementHonQPack {
    honQPack++;
}

- (IBAction)incrementDotaQPack {
    dotaQPack++;
}

- (IBAction)incrementDotaCPack {
    dotaCPack++;
}













// Returns the directory the application uses to store the Core Data store file. This code uses a directory named "LVF.GameQ-Stationary" in the user's Application Support directory.
- (NSURL *)applicationFilesDirectory
{
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *appSupportURL = [[fileManager URLsForDirectory:NSApplicationSupportDirectory inDomains:NSUserDomainMask] lastObject];
    return [appSupportURL URLByAppendingPathComponent:@"LVF.GameQ-Stationary"];
}

// Creates if necessary and returns the managed object model for the application.
- (NSManagedObjectModel *)managedObjectModel
{
    if (_managedObjectModel) {
        return _managedObjectModel;
    }
	
    NSURL *modelURL = [[NSBundle mainBundle] URLForResource:@"GameQ-Stationary" withExtension:@"momd"];
    _managedObjectModel = [[NSManagedObjectModel alloc] initWithContentsOfURL:modelURL];
    return _managedObjectModel;
}

// Returns the persistent store coordinator for the application. This implementation creates and return a coordinator, having added the store for the application to it. (The directory for the store is created, if necessary.)
- (NSPersistentStoreCoordinator *)persistentStoreCoordinator
{
    if (_persistentStoreCoordinator) {
        return _persistentStoreCoordinator;
    }
    
    NSManagedObjectModel *mom = [self managedObjectModel];
    if (!mom) {
        NSLog(@"%@:%@ No model to generate a store from", [self class], NSStringFromSelector(_cmd));
        return nil;
    }
    
    NSFileManager *fileManager = [NSFileManager defaultManager];
    NSURL *applicationFilesDirectory = [self applicationFilesDirectory];
    NSError *error = nil;
    
    NSDictionary *properties = [applicationFilesDirectory resourceValuesForKeys:@[NSURLIsDirectoryKey] error:&error];
    
    if (!properties) {
        BOOL ok = NO;
        if ([error code] == NSFileReadNoSuchFileError) {
            ok = [fileManager createDirectoryAtPath:[applicationFilesDirectory path] withIntermediateDirectories:YES attributes:nil error:&error];
        }
        if (!ok) {
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    } else {
        if (![properties[NSURLIsDirectoryKey] boolValue]) {
            // Customize and localize this error.
            NSString *failureDescription = [NSString stringWithFormat:@"Expected a folder to store application data, found a file (%@).", [applicationFilesDirectory path]];
            
            NSMutableDictionary *dict = [NSMutableDictionary dictionary];
            [dict setValue:failureDescription forKey:NSLocalizedDescriptionKey];
            error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:101 userInfo:dict];
            
            [[NSApplication sharedApplication] presentError:error];
            return nil;
        }
    }
    
    NSURL *url = [applicationFilesDirectory URLByAppendingPathComponent:@"GameQ-Stationary.storedata"];
    NSPersistentStoreCoordinator *coordinator = [[NSPersistentStoreCoordinator alloc] initWithManagedObjectModel:mom];
    if (![coordinator addPersistentStoreWithType:NSXMLStoreType configuration:nil URL:url options:nil error:&error]) {
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _persistentStoreCoordinator = coordinator;
    
    return _persistentStoreCoordinator;
}

// Returns the managed object context for the application (which is already bound to the persistent store coordinator for the application.) 
- (NSManagedObjectContext *)managedObjectContext
{
    if (_managedObjectContext) {
        return _managedObjectContext;
    }
    
    NSPersistentStoreCoordinator *coordinator = [self persistentStoreCoordinator];
    if (!coordinator) {
        NSMutableDictionary *dict = [NSMutableDictionary dictionary];
        [dict setValue:@"Failed to initialize the store" forKey:NSLocalizedDescriptionKey];
        [dict setValue:@"There was an error building up the data file." forKey:NSLocalizedFailureReasonErrorKey];
        NSError *error = [NSError errorWithDomain:@"YOUR_ERROR_DOMAIN" code:9999 userInfo:dict];
        [[NSApplication sharedApplication] presentError:error];
        return nil;
    }
    _managedObjectContext = [[NSManagedObjectContext alloc] init];
    [_managedObjectContext setPersistentStoreCoordinator:coordinator];

    return _managedObjectContext;
}

// Returns the NSUndoManager for the application. In this case, the manager returned is that of the managed object context for the application.
- (NSUndoManager *)windowWillReturnUndoManager:(NSWindow *)window
{
    return [[self managedObjectContext] undoManager];
}

// Performs the save action for the application, which is to send the save: message to the application's managed object context. Any encountered errors are presented to the user.
- (IBAction)saveAction:(id)sender
{
    NSError *error = nil;
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing before saving", [self class], NSStringFromSelector(_cmd));
    }
    
    if (![[self managedObjectContext] save:&error]) {
        [[NSApplication sharedApplication] presentError:error];
    }
}

- (NSApplicationTerminateReply)applicationShouldTerminate:(NSApplication *)sender
{
    // Save changes in the application's managed object context before the application terminates.
    
    if (!_managedObjectContext) {
        return NSTerminateNow;
    }
    
    if (![[self managedObjectContext] commitEditing]) {
        NSLog(@"%@:%@ unable to commit editing to terminate", [self class], NSStringFromSelector(_cmd));
        return NSTerminateCancel;
    }
    
    if (![[self managedObjectContext] hasChanges]) {
        return NSTerminateNow;
    }
    
    NSError *error = nil;
    if (![[self managedObjectContext] save:&error]) {

        // Customize this code block to include application-specific recovery steps.              
        BOOL result = [sender presentError:error];
        if (result) {
            return NSTerminateCancel;
        }

        NSString *question = NSLocalizedString(@"Could not save changes while quitting. Quit anyway?", @"Quit without saves error question message");
        NSString *info = NSLocalizedString(@"Quitting now will lose any changes you have made since the last successful save", @"Quit without saves error question info");
        NSString *quitButton = NSLocalizedString(@"Quit anyway", @"Quit anyway button title");
        NSString *cancelButton = NSLocalizedString(@"Cancel", @"Cancel button title");
        NSAlert *alert = [[NSAlert alloc] init];
        [alert setMessageText:question];
        [alert setInformativeText:info];
        [alert addButtonWithTitle:quitButton];
        [alert addButtonWithTitle:cancelButton];

        NSInteger answer = [alert runModal];
        
        if (answer == NSAlertAlternateReturn) {
            return NSTerminateCancel;
        }
    }

    return NSTerminateNow;
}

@end
