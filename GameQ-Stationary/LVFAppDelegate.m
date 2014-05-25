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
#define kNotRunningGameQ 4 //self explanatory

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
        if (txtEmail.stringValue.length > 2 && txtPassword.stringValue.length > 5) {
            if ([txtEmail.stringValue rangeOfString:@"@"].location != NSNotFound) {
                
                
                
                if ([txtEmail.stringValue rangeOfString:@"\""].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\""].location == NSNotFound &&
                    [txtEmail.stringValue rangeOfString:@"\\"].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\\"].location == NSNotFound) {
                    //what we wanna do
                    [_dataHandler setEmail:txtEmail.stringValue];
                    [_connectionsHandler loginWithUser:txtEmail.stringValue andPass:txtPassword.stringValue];
                    
                } else {
                    [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified email or password contains illegal characters"] runModal];
                }
            } else {
                [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified email is invalid"] runModal];
            }
        } else {
            [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Password must be a minimum of 6 characters"] runModal];
        }
        
        
        
        
        
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter a valid email address and password"] runModal];
    }
    
}
// pressed button that they dont have an account, link them to signup page!
    /*
-(void)linkmethod
{
    NSURL *registerURL = [[NSURL alloc] initWithString:REGISTER_URL];
    [[NSWorkspace sharedWorkspace] openURL:registerURL];
}*/

- (void)application:(NSApplication*)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData*)deviceToken
{
    
	NSLog(@"My token is: %@", deviceToken);
    
    NSString *oldToken = [_dataHandler getToken];
	NSString *newToken = [deviceToken description];
	newToken = [newToken stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"<>"]];
	newToken = [newToken stringByReplacingOccurrencesOfString:@" " withString:@""];
    
	NSLog(@"My token is: %@", newToken);
    [_dataHandler setToken:newToken];
	if ([_dataHandler getBolIsLoggedIn] && ![newToken isEqualToString:oldToken])
	{
		[_connectionsHandler upTokenWithToken:newToken andDeviceName:[_dataHandler getDeviceID] andEmail:[_dataHandler getEmail]];
        
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
    _bolQueueCD = false;
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
    
    self.statusBar.image = [NSImage imageNamed:@"Qblack.png"];
    [self.statusBar setHighlightMode:YES];
    [self.statusBar setAlternateImage:[NSImage imageNamed:@"Qwhite.png"]];
    self.statusBar.menu = self.mainMenu;
    self.statusBar.highlightMode = TRUE;
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToUIElementApplication);
    
    
    dotaQBuffer = [[LVFBuffer alloc] init];
    NSLog(@"init delegate");
    
    
    
    
    

    
    //setup the login window
    NSRect winFrame = NSRectFromCGRect(CGRectMake(0, 0, 573, 473));
    NSUInteger stylemask = /*NSTexturedBackgroundWindowMask|*/NSClosableWindowMask|NSMiniaturizableWindowMask|NSTitledWindowMask/*|NSResizableWindowMask*/;
    loginWindow = [[NSWindow alloc] initWithContentRect:winFrame styleMask:stylemask backing:NSBackingStoreBuffered defer:YES];
    [loginWindow setReleasedWhenClosed:NO];
    [loginWindow center];
    
    //[loginWindow setBackgroundColor:grad ];
    //[loginWindow setBackgroundColor:[NSColor colorWithCalibratedRed:1 green:1 blue:1 alpha:1.0] ];
    [loginWindow setTitle:@"GameQ"];
    LVFWindowViewSubclass *winView = [[LVFWindowViewSubclass alloc] initWithFrame:winFrame];
    [loginWindow setContentView:winView];
    
    NSRect mailFrame = NSRectFromCGRect(CGRectMake(winFrame.size.width/2-233.5, winFrame.size.height-80, 217, 25));
    NSRect passFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, mailFrame.origin.y-30, 217, 25));
    
   
    
    
    NSRect questionFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, passFrame.origin.y-30, 217, 25));
    NSRect answerFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, questionFrame.origin.y-30, 217, 25));
    NSRect firstNameFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, answerFrame.origin.y-30, 217, 25));
    NSRect lastNameFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, firstNameFrame.origin.y-30, 217, 25));
    NSRect yobFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, lastNameFrame.origin.y-30, 217, 25));
    

    
    NSRect countryFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, yobFrame.origin.y-30, 100, 25));
    NSRect genderFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x+3, countryFrame.origin.y-45, 140, 60));
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(countryFrame.origin.x+countryFrame.size.width+20, passFrame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(countryFrame.origin.x, passFrame.origin.y-35, 100, 25));
    NSRect regFrame = NSRectFromCGRect(CGRectMake(countryFrame.origin.x, 170, 220, 25));
    
    
    
    txtPassword = [[NSSecureTextField alloc] initWithFrame:passFrame];
    txtEmail = [[NSTextField alloc] initWithFrame:mailFrame];
    
    btnSignUp = [[NSButton alloc] initWithFrame:regFrame];
    btnLogin = [[NSButton alloc] initWithFrame:loginFrame];
    _btnQuestion = [[NSButton alloc] initWithFrame:questionBtnFrame];
    [[txtPassword cell] setPlaceholderString:@"Password"];
    [[txtEmail cell] setPlaceholderString:@"E-Mail"];
    [btnLogin setTitle:@"Log In"];
    [btnSignUp setTitle:@"Join GameQ"];
    [btnLogin setBezelStyle:NSRoundedBezelStyle];
    
    
    
    [btnLogin setTarget:self];
    [btnLogin setAction:@selector(attemptLogin)];
    [btnSignUp setTarget:self];
    [btnSignUp setAction:@selector(setupRegister)];
    [btnSignUp setButtonType:NSMomentaryChangeButton];
    [btnLogin setButtonType:NSMomentaryChangeButton];
    [btnSignUp setBordered:NO];
    [btnSignUp setBezelStyle:NSRoundedBezelStyle];
    [btnLogin setBordered:NO];
    [_btnQuestion setTitle:@"Forgot Password"];
    [_btnQuestion setBezelStyle:NSRoundedBezelStyle];
    [_btnQuestion setTarget:self];
    [_btnQuestion setAction:@selector(setupQuestion)];
    [_btnQuestion setButtonType:NSMomentaryChangeButton];
    [_btnQuestion setBordered:NO];
    
    
    [btnLogin.cell setHighlightsBy:NSContentsCellMask];
    [btnLogin.cell setHighlightsBy:NSContentsCellMask];
    [btnLogin.cell setHighlightsBy:NSContentsCellMask];
    
    [btnLogin setImage:[NSImage imageNamed:@"Gray.png"]];
    [btnSignUp setImage:[NSImage imageNamed:@"Gray.png"]];
    [_btnQuestion setImage:[NSImage imageNamed:@"Gray.png"]];
    [btnLogin setAlternateImage:[NSImage imageNamed:@"GQLogo.png"]];
    [btnSignUp setAlternateImage:[NSImage imageNamed:@"GQLogo.png"]];
    [_btnQuestion setAlternateImage:[NSImage imageNamed:@"GQLogo.png"]];
    
    
    _txtFirstName = [[NSTextField alloc] initWithFrame:firstNameFrame];
    _txtLastName = [[NSTextField alloc] initWithFrame:lastNameFrame];
    _txtYOB = [[NSTextField alloc] initWithFrame:yobFrame];
    _rolloverCountry = [[NSPopUpButton alloc] initWithFrame:countryFrame pullsDown:YES];
    _segSex = [[NSSegmentedControl alloc] initWithFrame:genderFrame];
    _txtQuestion = [[NSTextField alloc] initWithFrame:questionFrame];
    _txtAnswer = [[NSSecureTextField alloc] initWithFrame:answerFrame];
    
    [_segSex setSegmentCount:2];
    [_segSex setImage:[NSImage imageNamed:@"i5woman.png"] forSegment:0];
    [_segSex setImage:[NSImage imageNamed:@"i5man.png"] forSegment:1];
    [_segSex setSegmentStyle:NSSegmentStyleCapsule];
    
    [[_txtYOB cell] setPlaceholderString:@"Year of Birth"];
    [[_txtFirstName cell] setPlaceholderString:@"First Name"];
    [[_txtLastName cell] setPlaceholderString:@"Last Name"];
    [[_txtQuestion cell] setPlaceholderString:@"Secret Question"];
    [[_txtAnswer cell] setPlaceholderString:@"Secret Answer"];
    
    
    NSRect cFrame = NSRectFromCGRect(CGRectMake(25, -2, 520, 159));
    NSImageView *cView = [[NSImageView alloc] initWithFrame:cFrame];
    [cView setImage:[NSImage imageNamed:@"GameQ.png"]];
    [loginWindow.contentView addSubview:cView];
    
    NSRect aFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x - 15, countryFrame.origin.y-30, 247, 300));
    NSImageView *aView = [[NSImageView alloc] initWithFrame:aFrame];
    [aView setImageScaling:NSImageScaleAxesIndependently];
    [aView setImage:[NSImage imageNamed:@"Gray.png"]];
    [loginWindow.contentView addSubview:aView];
    
    NSRect bFrame = NSRectFromCGRect(CGRectMake(winFrame.size.width/2 + 1.5, countryFrame.origin.y-30, 247, 300));
    NSImageView *bView = [[NSImageView alloc] initWithFrame:bFrame];
    [bView setImageScaling:NSImageScaleAxesIndependently];
    [bView setImage:[NSImage imageNamed:@"Gray.png"]];
    [loginWindow.contentView addSubview:bView];
    
    
    
    [loginWindow.contentView addSubview:_txtFirstName];
    [loginWindow.contentView addSubview:_txtLastName];
    [loginWindow.contentView addSubview:txtPassword];
    [loginWindow.contentView addSubview:txtEmail];
    [loginWindow.contentView addSubview:_txtYOB];
    [loginWindow.contentView addSubview:_segSex];
    [loginWindow.contentView addSubview:_rolloverCountry];
    [loginWindow.contentView addSubview:_txtAnswer];
    [loginWindow.contentView addSubview:_txtQuestion];
    [loginWindow.contentView addSubview:btnLogin];
    [loginWindow.contentView addSubview:btnSignUp];
    [loginWindow.contentView addSubview:_btnQuestion];
    [[loginWindow contentView] setAutoresizesSubviews:YES];
    [btnLogin setKeyEquivalent:@"\r"];
    [loginWindow setDelegate:_windowHandler];
    [_txtFirstName setEnabled:NO];
    [_txtLastName setEnabled:NO];
    [_txtYOB setEnabled:NO];
    [_segSex setEnabled:NO];
    [_rolloverCountry setEnabled:NO];
    [_txtQuestion setEnabled:NO];
    [_txtAnswer setEnabled:NO];
    [_txtAnswer setAlphaValue:0];
    [_txtQuestion setAlphaValue:0];
    [_txtFirstName setAlphaValue:0];
    [_txtLastName setAlphaValue:0];
    [_txtYOB setAlphaValue:0];
    [_segSex setAlphaValue:0];
    [_rolloverCountry setAlphaValue:0];
    
    
    
    
    
    
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

    
-(void) attemptRegister{
    NSLog(@"attempting register!");
    
    //checks if any text exists in the fields
    if (![txtEmail.stringValue isEqual:@""] && ![txtPassword.stringValue isEqual:@""]) {
        if (txtEmail.stringValue.length > 2 && txtPassword.stringValue.length > 5 && _txtAnswer.stringValue.length > 5) {
            if ([txtEmail.stringValue rangeOfString:@"@"].location != NSNotFound) {
                
                
                
                if ([txtEmail.stringValue rangeOfString:@"\""].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\""].location == NSNotFound &&
                    [txtEmail.stringValue rangeOfString:@"\\"].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\\"].location == NSNotFound && [_txtAnswer.stringValue rangeOfString:@"\""].location == NSNotFound && [_txtQuestion.stringValue rangeOfString:@"\""].location == NSNotFound &&
                    [_txtQuestion.stringValue rangeOfString:@"\\"].location == NSNotFound && [_txtAnswer.stringValue rangeOfString:@"\\"].location == NSNotFound) {
                    //what we wanna do
                    [_connectionsHandler registerWithEmail:txtEmail.stringValue andPass:txtPassword.stringValue andSecretQuestion:_txtQuestion.stringValue andSecret:_txtAnswer.stringValue andFirsName:_txtFirstName.stringValue andLastName:_txtLastName.stringValue andGender:1 andYOB:_txtYOB.stringValue andCountry:@"sweden"];
                    
                } else {
                    [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified details contain illegal characters"] runModal];
                }
            } else {
                [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified email is invalid"] runModal];
            }
        } else {
            [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Password and secret must be a minimum of 6 characters"] runModal];
        }
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter valid details!"] runModal];
    }
    
    
    
    
    
    
    
}
    
-(void) setupRegister{
    
    NSLog(@"login = REGISTER, @attemptRegister ie postar!!!!!");
    
    [btnLogin setAction:@selector(attemptRegister)];
    [_btnQuestion setAction:@selector(setupLogin)];
    [_btnQuestion setTitle:@"Cancel"];
    [btnLogin setTitle:@"Join GameQ"];
    
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, _txtFirstName.frame.origin.y-2, 100, 25));
    NSRect qstFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    
    [[btnLogin animator]setFrame:loginFrame];
    [[_btnQuestion animator]setFrame:qstFrame];
    //[[_txtFirstName animator]setAlphaValue:1];
    //[[_txtFirstName animator]setEnabled:YES];
    //[[_txtLastName animator]setAlphaValue:1];
    //[[_txtLastName animator]setEnabled:YES];
    //[[_txtYOB animator]setAlphaValue:1];
    //[[_txtYOB animator]setEnabled:YES];
    //[[_segSex animator]setAlphaValue:1];
    //[[_segSex animator]setEnabled:YES];
    //[[_rolloverCountry animator]setAlphaValue:1];
    //[[_rolloverCountry animator]setEnabled:YES];
    [[_txtQuestion animator]setEnabled:YES];
    [[_txtAnswer animator]setEnabled:YES];
    [[_txtAnswer animator]setAlphaValue:1];
    [[_btnQuestion animator] setAlphaValue:1];
    [[_txtQuestion animator]setAlphaValue:1];
    [[txtPassword animator]setAlphaValue:1];
    [[txtPassword animator]setEnabled:YES];
    [[txtEmail animator]setAlphaValue:1];
    [[txtEmail animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:0];
    [[btnSignUp animator]setEnabled:NO];
    
}

-(void) setupEditProfile{
    
    NSLog(@"login = REGISTER, @attemptRegister ie postar!!!!!");
    
    [btnLogin setAction:@selector(attemptRegister)];
    [btnSignUp setAction:@selector(setupLogin)];
    [btnSignUp setTitle:@"Cancel"];
    [btnLogin setTitle:@"Join GameQ"];
    
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, _rolloverCountry.frame.origin.y-2, 100, 25));
    
    
    
    [[btnLogin animator]setFrame:loginFrame];
    [[_txtFirstName animator]setAlphaValue:1];
    [[_txtFirstName animator]setEnabled:YES];
    [[_txtLastName animator]setAlphaValue:1];
    [[_txtLastName animator]setEnabled:YES];
    [[_txtYOB animator]setAlphaValue:1];
    [[_txtYOB animator]setEnabled:YES];
    [[_segSex animator]setAlphaValue:1];
    [[_segSex animator]setEnabled:YES];
    [[_rolloverCountry animator]setAlphaValue:1];
    [[_rolloverCountry animator]setEnabled:YES];
    [[_txtQuestion animator]setEnabled:YES];
    [[_txtAnswer animator]setEnabled:YES];
    [[_txtAnswer animator]setAlphaValue:1];
    [[_btnQuestion animator] setAlphaValue:0];
    [[_txtQuestion animator]setAlphaValue:1];
    
}

-(void) setupLogin{
    
    [btnLogin setAction:@selector(attemptLogin)];
    [btnSignUp setAction:@selector(setupRegister)];
    [btnSignUp setTitle:@"Join GameQ"];
    [btnLogin setTitle:@"Log In"];
    [_btnQuestion setTitle:@"Forgot?"];
    [_btnQuestion setAction:@selector(setupQuestion)];
    [txtEmail.cell setPlaceholderString:@"E-Mail"];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtPassword.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    [[_btnQuestion animator] setFrame:questionBtnFrame];
    [[btnLogin animator] setFrame:loginFrame];
    [[_txtFirstName animator] setAlphaValue:0];
    [[_txtLastName animator] setAlphaValue:0];
    [[_txtYOB animator] setAlphaValue:0];
    [[_segSex animator] setAlphaValue:0];
    [[_rolloverCountry animator] setAlphaValue:0];
    [_txtFirstName setEnabled:NO];
    [_txtLastName setEnabled:NO];
    [_txtYOB setEnabled:NO];
    [_segSex setEnabled:NO];
    [_rolloverCountry setEnabled:NO];
    [_txtQuestion setEnabled:NO];
    [_txtAnswer setEnabled:NO];
    [[_txtAnswer animator]setAlphaValue:0];
    [[_txtQuestion animator]setAlphaValue:0];
    [[_btnQuestion animator] setAlphaValue:1];
    [[txtPassword animator]setAlphaValue:1];
    [[txtPassword animator]setEnabled:YES];
    [[txtEmail animator]setAlphaValue:1];
    [[txtEmail animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:1];
    [[btnSignUp animator]setEnabled:YES];
    
    
}

- (void) tearDownLoggedIn
{
    [loginWindow close];
}

- (void) setupLoggedIn
{
    [self tearDownLoggedIn];
}
    
-(void) setupQuestion {
    [_btnQuestion setTitle:@"cancel"];
    [btnLogin setTitle:@"OK"];
    [_btnQuestion setAction:@selector(setupLogin)];
    [btnLogin setAction:@selector(checkQuestion)];
    [txtPassword setEnabled:false];
    
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtEmail.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    
    [[_btnQuestion animator]setFrame:questionBtnFrame];
    [[btnLogin animator]setFrame:loginFrame];
    [[_txtFirstName animator]setAlphaValue:0];
    [[_txtFirstName animator]setEnabled:NO];
    [[_txtLastName animator]setAlphaValue:0];
    [[_txtLastName animator]setEnabled:NO];
    [[_txtYOB animator]setAlphaValue:0];
    [[_txtYOB animator]setEnabled:NO];
    [[_segSex animator]setAlphaValue:0];
    [[_segSex animator]setEnabled:NO];
    [[_rolloverCountry animator]setAlphaValue:0];
    [[_rolloverCountry animator]setEnabled:NO];
    [[_txtQuestion animator]setEnabled:NO];
    [[_txtAnswer animator]setEnabled:NO];
    [[_txtAnswer animator]setAlphaValue:0];
    [[_txtQuestion animator]setAlphaValue:0];
    [[txtPassword animator]setAlphaValue:0];
    [[txtPassword animator]setEnabled:NO];
    [[_segSex animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:1];
    [[btnSignUp animator]setEnabled:YES];
    
    
    
    
   
    
}
    
-(void) checkQuestion{
    [self disableButtons];
    [_connectionsHandler getSecretPost:txtEmail.stringValue];
    _strQuestionMail = [[NSString alloc] initWithFormat:@"%@", txtEmail.stringValue];
    
    
}
-(void) setupAnswerWithQuestion:(NSString*)question {
    [self enableButtons];
    _strQuestion = [[NSString alloc] initWithString:question];
    [txtEmail.cell setPlaceholderString:question];
    [btnLogin setTitle:@"OK"];
    [btnLogin setAction:@selector(validateQuestion)];
}

- (void) enableButtons
{
    [btnLogin setEnabled:YES];
    [btnSignUp setEnabled:YES];
    [_btnQuestion setEnabled:YES];
    [btnLog setEnabled:YES];
    
}

- (void) disableButtons
{
    [btnLogin setEnabled:NO];
    [btnSignUp setEnabled:NO];
    [_btnQuestion setEnabled:NO];
    [btnLog setEnabled:NO];
    
}

-(void) validateQuestion{
    [self disableButtons];
    [_connectionsHandler chkSecretForEmail:_strQuestionMail withSecret:txtEmail.stringValue andSecretQuestion:_strQuestion];
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
            printf("ip_len: %d", ntohs(ip->ip_len));
            
            
            printf("   Src port: %d\n", ntohs(udp->uh_sport));
            printf("   Dst port: %d\n", ntohs(udp->uh_dport));
        
        
            
            int dport = ntohs(udp->uh_dport);
            int sport = ntohs(udp->uh_sport);
            if (dport <= 11335 && dport >= 11235) {
                
                NSLog(@"Hon Packet");
                [self incrementHonQPack];
                NSLog(@"%d",[self honQPack]);
            }
            
            if (sport >= 27015 && sport <= 27020 && ntohs(ip->ip_len) <= 736 && ntohs(ip->ip_len) >= 586) {
                //checks wirelength 600-750
                
                // size_udp == wirelength - 34
                // ip_len == size_udp + 20
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
        NSLog(@"toggleOn");
    } else {
        [self toggleOff:nil];
        NSLog(@"toggleOff");
    }
    NSLog(@"arglar %@", [NSNumber numberWithBool:bolIsActive]);
    bolIsActive = !bolIsActive;
    NSLog(@"arglar %@", [NSNumber numberWithBool:bolIsActive]);
    
}

- (IBAction)toggleOff:(id)sender {
    [btnToggleActive setTitle:@"Start Monitoring"];
    [self.statusBar setImage:[NSImage imageNamed:@"Qblack.png"]];
    [_btnStatus2 setTitle:@"Status: Online"];
    pcap_breakloop(handle);
    printf("\nCapture complete.\n");
    [self performSelectorOnMainThread:@selector(stopTimer) withObject:nil waitUntilDone:false];
    bolFirstTick = true;
    printf("\nCapture complete.\n");
    
    
    
}

- (IBAction)toggleOn:(id)sender {
    [_btnStatus2 setTitle:@"Status: Tracking"];
        
    printf("\nCapture started.\n");
    [self performSelectorOnMainThread:@selector(startTimer) withObject:nil waitUntilDone:false];
    [btnToggleActive setTitle:@"Stop Monitoring"];
    printf("\nCapture started.\n");
    [self.statusBar setImage:[NSImage imageNamed:@"Qblue.png"]];
    pcap_loop(handle, num_packets, got_packet, self);
}

// ---------------------------------------------  end toggle  ---------------------------------------------

- (void) startTimer {
    countdownQuickTimer = [NSTimer timerWithTimeInterval:1 target:self selector:@selector(tack:) userInfo:nil repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:countdownQuickTimer forMode:NSDefaultRunLoopMode];
    
    _upTimeTimer = [NSTimer timerWithTimeInterval:60 target:self selector:@selector(upTime) userInfo:nil repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:_upTimeTimer forMode:NSDefaultRunLoopMode];
    
    //countdownSlowTimer = [NSTimer timerWithTimeInterval:5 target:self selector:@selector(tick:) userInfo:nil repeats:YES];
    //[[NSRunLoop currentRunLoop] addTimer:countdownSlowTimer forMode:NSDefaultRunLoopMode];
}
- (void) stopTimer {
    [countdownQuickTimer invalidate];
    //[countdownSlowTimer invalidate];
}

- (void) upTime
{
    [_connectionsHandler upTimeForToken:[_dataHandler getToken]];
}

// reg / login button is selected from the GQ toolbar menu
- (IBAction)log:(id)sender
{
    
    [btnToggleActive setEnabled:NO];
    if(bolLoggedIn) {
        [_connectionsHandler logoutPostFromToken:([_dataHandler getToken])];
        
    } else {
        
        //[loginWindow close];
        ProcessSerialNumber psn = { 0, kCurrentProcess };
        TransformProcessType(&psn, kProcessTransformToForegroundApplication);
        
        //[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        //[[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
        //[loginWindow makeKeyWindow];
        [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
        [self setupLogin];
        [loginWindow center];
        [loginWindow orderFrontRegardless];
        [loginWindow makeKeyAndOrderFront:nil];
        //[loginWindow orderFront:nil];
        NSLog(@"showing window");
        
    }
}

//is this method even used? or have i forgotten to remove it? attemptLogin used instead?!?
- (void)logIn
{
    
    
    
    [_connectionsHandler loginWithUser:txtEmail.stringValue andPass:txtPassword.stringValue];
    
    
}

- (void) setConnected
{
    
    [_connectionsHandler.gqConnect postNow:[NSString stringWithFormat:@"token=%@&deviceName=%@&email=%@", [_dataHandler getToken], [_dataHandler getDeviceID], [_dataHandler getEmail]] to:updateTokenURL];
    NSLog(@"token posted with token:%@ devName:%@ and email:%@", [_dataHandler getToken], [_dataHandler getDeviceID], [_dataHandler getEmail]);
    [btnLog setTitle:@"Log Out"];
    [btnToggleActive setEnabled:true];
    bolLoggedIn = YES;
    [_dataHandler setBolIsLoggedIn:[NSNumber numberWithBool:YES]];
    [_dataHandler setEmail:[txtEmail stringValue]];
    NSLog(@"set email to %@", txtEmail.stringValue);
    NSLog(@"email is %@", [_dataHandler getEmail]);
    [_dataHandler setPass:[txtPassword stringValue]];
    [txtPassword setStringValue:@""];
    [_btnStatus setTitle:[NSString stringWithFormat:@"%@", [_dataHandler getEmail]]];
    [_btnStatus2 setTitle:@"Status: Online"];
    [_btnStatus setHidden:NO];
    bolIsActive = NO;
    [self toggle:nil];
    [self.statusBar setImage:[NSImage imageNamed:@"Qblue.png"]];
    // following tells the server the client is online but no games have been launched
    [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:kNOGAME] andStatus:[NSNumber numberWithInt:kOFFLINE] andToken:[_dataHandler getToken]];
    [self setupLoggedIn];
    
    
    
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
    [self.btnLog setTitle:@"Log In / Sign up"];
    [btnToggleActive setEnabled:NO];
    [_btnStatus setHidden:YES];
    [_btnStatus2 setTitle:@"Status: Offline"];
    [_upTimeTimer invalidate];
}






// quits the app
- (IBAction)quit:(id)sender {
    [self toggleOff:(nil)];
    pcap_freecode(&fp);
	pcap_close(handle);
    exit(0);
    
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
    NSLog(@"HoN");
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
    NSLog(@"DotA");
    [dotaQBuffer increment:dotaQPack];
    NSLog(@"buffer: %i", dotaQBuffer.bufferValue);
    NSLog(@"dota running: %i", dotaRunning);
    if (dotaQBuffer.bufferValue > 0 && dotaRunning) {
        [self inGame:kDOTA2]; //potentially sends notification
    }
    if (dotaCPack > 1 && dotaRunning) {
        // user is in game
        bolFirstTick = 1; //tricks the app in to not sending a notification
                          // this is not the queue pop, but the fact of being in a game
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
    bool bolOnline = [[bolOnlineArray objectAtIndex:game] boolValue];
    [bolOnlineArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
    [bolInGameArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
     for (NSNumber *numberobject in bolInGameArray) {
        if (numberobject.boolValue == true) {
            return;
        }
    }
    for (NSNumber *numberobject in bolOnlineArray) {
        if (numberobject.boolValue == true) {
            return;
        }
    }
    NSLog(@"called method \"offline\"");
    if (!bolOnline) {
        // do nothing if status was already offline, (initialized to offline)
    } else {
        
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kOFFLINE] andToken:[_dataHandler getToken]];
    }
    
    
}

//called whenever online status is detected
- (IBAction)online:(int)game {
    if (_bolQueueCD) {
        return;
    }
    
    [bolInGameArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
    for (NSNumber *numberobject in bolInGameArray) {
        if (numberobject.boolValue == true) {
            return;
        }
    }
    
    NSLog(@"called method \"online\"");
    if ([[bolOnlineArray objectAtIndex:game] boolValue] && ![[bolInGameArray objectAtIndex:game] boolValue]) {
        // do nothing if status already online, (initialized to offline)
    } else {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kONLINE] andToken:[_dataHandler getToken]];
        
    }
    [bolOnlineArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    
}

//executes every quick timer user is in a match
- (IBAction)inGame:(int)game {
    
    NSLog(@"called method \"ingame\"");
    // if its the first tick
    if (bolFirstTick) {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kINGAME] andToken:[_dataHandler getToken]];
        NSLog(@"ingame- just updating");
        
    } else if(!bolFirstTick && [[bolInGameArray objectAtIndex:game] boolValue]){
        //do nothing
        NSLog(@"ingame- do nothing");
        
    } else if(!bolFirstTick && ![[bolInGameArray objectAtIndex:game] boolValue]) {
        [_connectionsHandler pushNotificationForGame:[NSNumber numberWithInt:game] andToken:[_dataHandler getToken] andEmail:[_dataHandler getEmail]];
        NSLog(@"ingame- pushing");
    }
    [bolInGameArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    [bolOnlineArray replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    _bolQueueCD = true;
    _queuePopCooldownTimer = [NSTimer timerWithTimeInterval:5 target:self selector:@selector(resetQueueCooldown) userInfo:nil repeats:NO];
    [[NSRunLoop mainRunLoop] addTimer:_queuePopCooldownTimer forMode:NSDefaultRunLoopMode];
    
}

- (void) resetQueueCooldown
{
    [_queuePopCooldownTimer invalidate];
    _bolQueueCD = false;
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
    printf("Incrementing HonQPack");
    honQPack++;
}

- (IBAction)incrementDotaQPack {
    printf("Incrementing DotaQPack");
    dotaQPack++;
}

- (IBAction)incrementDotaCPack {
    printf("Incrementing DotaCPack");
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
