//
//  LVFAppDelegate.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 10/24/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFAppDelegate.h"






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
@synthesize dota174Pack;
@synthesize dota190Pack;
@synthesize dota206Pack;
@synthesize dotaCPack;
@synthesize csgoQPack;
@synthesize csgoGamePack;
@synthesize bolFirstTick;
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
//char filter_exp[] = "udp dst portrange 11235-11335 or tcp dst port 11031 or udp src portrange 27015-28999 or udp dst port 27005";	/* The filter expression */
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

#include <stdio.h>

#include <CoreFoundation/CoreFoundation.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/network/IOEthernetInterface.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/network/IOEthernetController.h>

static kern_return_t FindEthernetInterfaces(io_iterator_t *matchingServices);
static kern_return_t GetMACAddress(io_iterator_t intfIterator, UInt8 *MACAddress, UInt8 bufferSize);

// Returns an iterator containing the primary (built-in) Ethernet interface. The caller is responsible for
// releasing the iterator after the caller is done with it.
static kern_return_t FindEthernetInterfaces(io_iterator_t *matchingServices)
{
    kern_return_t           kernResult;
    CFMutableDictionaryRef	matchingDict;
    CFMutableDictionaryRef	propertyMatchDict;
    
    // Ethernet interfaces are instances of class kIOEthernetInterfaceClass.
    // IOServiceMatching is a convenience function to create a dictionary with the key kIOProviderClassKey and
    // the specified value.
    matchingDict = IOServiceMatching(kIOEthernetInterfaceClass);
    
    // Note that another option here would be:
    // matchingDict = IOBSDMatching("en0");
    // but en0: isn't necessarily the primary interface, especially on systems with multiple Ethernet ports.
    
    if (NULL == matchingDict) {
        printf("IOServiceMatching returned a NULL dictionary.\n");
    }
    else {
        // Each IONetworkInterface object has a Boolean property with the key kIOPrimaryInterface. Only the
        // primary (built-in) interface has this property set to TRUE.
        
        // IOServiceGetMatchingServices uses the default matching criteria defined by IOService. This considers
        // only the following properties plus any family-specific matching in this order of precedence
        // (see IOService::passiveMatch):
        //
        // kIOProviderClassKey (IOServiceMatching)
        // kIONameMatchKey (IOServiceNameMatching)
        // kIOPropertyMatchKey
        // kIOPathMatchKey
        // kIOMatchedServiceCountKey
        // family-specific matching
        // kIOBSDNameKey (IOBSDNameMatching)
        // kIOLocationMatchKey
        
        // The IONetworkingFamily does not define any family-specific matching. This means that in
        // order to have IOServiceGetMatchingServices consider the kIOPrimaryInterface property, we must
        // add that property to a separate dictionary and then add that to our matching dictionary
        // specifying kIOPropertyMatchKey.
        
        propertyMatchDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
													  &kCFTypeDictionaryKeyCallBacks,
													  &kCFTypeDictionaryValueCallBacks);
        
        if (NULL == propertyMatchDict) {
            printf("CFDictionaryCreateMutable returned a NULL dictionary.\n");
        }
        else {
            // Set the value in the dictionary of the property with the given key, or add the key
            // to the dictionary if it doesn't exist. This call retains the value object passed in.
            CFDictionarySetValue(propertyMatchDict, CFSTR(kIOPrimaryInterface), kCFBooleanTrue);
            
            // Now add the dictionary containing the matching value for kIOPrimaryInterface to our main
            // matching dictionary. This call will retain propertyMatchDict, so we can release our reference
            // on propertyMatchDict after adding it to matchingDict.
            CFDictionarySetValue(matchingDict, CFSTR(kIOPropertyMatchKey), propertyMatchDict);
            CFRelease(propertyMatchDict);
        }
    }
    
    // IOServiceGetMatchingServices retains the returned iterator, so release the iterator when we're done with it.
    // IOServiceGetMatchingServices also consumes a reference on the matching dictionary so we don't need to release
    // the dictionary explicitly.
    kernResult = IOServiceGetMatchingServices(kIOMasterPortDefault, matchingDict, matchingServices);
    if (KERN_SUCCESS != kernResult) {
        printf("IOServiceGetMatchingServices returned 0x%08x\n", kernResult);
    }
    
    return kernResult;
}

// Given an iterator across a set of Ethernet interfaces, return the MAC address of the last one.
// If no interfaces are found the MAC address is set to an empty string.
// In this sample the iterator should contain just the primary interface.
static kern_return_t GetMACAddress(io_iterator_t intfIterator, UInt8 *MACAddress, UInt8 bufferSize)
{
    io_object_t		intfService;
    io_object_t		controllerService;
    kern_return_t	kernResult = KERN_FAILURE;
    
    // Make sure the caller provided enough buffer space. Protect against buffer overflow problems.
	if (bufferSize < kIOEthernetAddressSize) {
		return kernResult;
	}
	
	// Initialize the returned address
    bzero(MACAddress, bufferSize);
    
    // IOIteratorNext retains the returned object, so release it when we're done with it.
    while ((intfService = IOIteratorNext(intfIterator)))
    {
        CFTypeRef	MACAddressAsCFData;
        
        // IONetworkControllers can't be found directly by the IOServiceGetMatchingServices call,
        // since they are hardware nubs and do not participate in driver matching. In other words,
        // registerService() is never called on them. So we've found the IONetworkInterface and will
        // get its parent controller by asking for it specifically.
        
        // IORegistryEntryGetParentEntry retains the returned object, so release it when we're done with it.
        kernResult = IORegistryEntryGetParentEntry(intfService,
												   kIOServicePlane,
												   &controllerService);
		
        if (KERN_SUCCESS != kernResult) {
            printf("IORegistryEntryGetParentEntry returned 0x%08x\n", kernResult);
        }
        else {
            // Retrieve the MAC address property from the I/O Registry in the form of a CFData
            MACAddressAsCFData = IORegistryEntryCreateCFProperty(controllerService,
																 CFSTR(kIOMACAddress),
																 kCFAllocatorDefault,
																 0);
            if (MACAddressAsCFData) {
                CFShow(MACAddressAsCFData); // for display purposes only; output goes to stderr
                
                // Get the raw bytes of the MAC address from the CFData
                CFDataGetBytes(MACAddressAsCFData, CFRangeMake(0, kIOEthernetAddressSize), MACAddress);
                CFRelease(MACAddressAsCFData);
            }
            
            // Done with the parent Ethernet controller object so we release it.
            (void) IOObjectRelease(controllerService);
        }
        
        // Done with the Ethernet interface object so we release it.
        (void) IOObjectRelease(intfService);
    }
    
    return kernResult;
}

unsigned char * main2()
{
    kern_return_t	kernResult = KERN_SUCCESS;
    io_iterator_t	intfIterator;
    UInt8			MACAddress[kIOEthernetAddressSize];
    
    kernResult = FindEthernetInterfaces(&intfIterator);
    
    if (KERN_SUCCESS != kernResult) {
        printf("FindEthernetInterfaces returned 0x%08x\n", kernResult);
    }
    else {
        kernResult = GetMACAddress(intfIterator, MACAddress, sizeof(MACAddress));
        
        if (KERN_SUCCESS != kernResult) {
            printf("GetMACAddress returned 0x%08x\n", kernResult);
        }
		else {
			printf("This system's built-in MAC address is %02x:%02x:%02x:%02x:%02x:%02x.\n",
                   MACAddress[0], MACAddress[1], MACAddress[2], MACAddress[3], MACAddress[4], MACAddress[5]);
		}
    }
    
    (void) IOObjectRelease(intfIterator);	// Release the iterator.
    
    
    

    return MACAddress;
}



- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
    
    
    
    //first init
    _dataHandler = [[LVFDataModel alloc] initWithAppDelegate:self];
    _wildCards = [[NSMutableDictionary alloc] init];
    
    
    
    NSLog(@"%@", [_dataHandler getDeviceID]);
    if ([_dataHandler getDeviceID] == NULL) {
        [_dataHandler setDeviceID: [[NSHost currentHost] localizedName]];
        SMLoginItemSetEnabled ((__bridge CFStringRef)@"LVF.GameQ-Launcher", YES);
    } else if ([[_dataHandler getDeviceID] isEqualToString:@""]) {
        [_dataHandler setDeviceID: [[NSHost currentHost] localizedName]];
        SMLoginItemSetEnabled ((__bridge CFStringRef)@"LVF.GameQ-Launcher", YES);
    }
    NSLog(@"%@", [_dataHandler getDeviceID]);
    
    
    
    //initailizing state
    _bolSpecialCD = false;
    _bolQueueCD = false;
    [[NSApplication sharedApplication] registerForRemoteNotificationTypes:(NSRemoteNotificationTypeAlert | NSRemoteNotificationTypeBadge | NSRemoteNotificationTypeSound)];
    _connectionsHandler = [[LVFConnections alloc] init];
    _windowHandler = [[LVFWindowHandler alloc] init];
    bolIsActive = false;
    bolFirstTick = true;
    
    
    
    
    NSLog(@"stored data:\r\nloggedin: %@\r\nemail: %@\r\ntoken: %@\r\npassword:%@ \r\ndeviceID:%@", [_dataHandler getBolIsLoggedIn], [_dataHandler getEmail], [_dataHandler getToken], @"like i'd tell you :P", [_dataHandler getDeviceID]);
    
    
    
    
    
    
    
    // creating statusbar item
    self.statusBar = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
    
    self.statusBar.image = [NSImage imageNamed:@"Qblack"];
    [self.statusBar setHighlightMode:YES];
    [self.statusBar setAlternateImage:[NSImage imageNamed:@"Qwhite"]];
    self.statusBar.menu = self.mainMenu;
    self.statusBar.highlightMode = TRUE;
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToUIElementApplication);
    
    
    _dotaQBuffer = [[LVFBuffer alloc] initWithSize:5];
    _dota174Buffer = [[LVFBuffer alloc] initWithSize:6];
    _dota190Buffer = [[LVFBuffer alloc] initWithSize:4];
    _dota206Buffer = [[LVFBuffer alloc] initWithSize:3];
    _dotaCBuffer = [[LVFBuffer alloc] initWithSize:5];
    _honQBuffer = [[LVFBuffer alloc] initWithSize:5];
    _csgoQBuffer = [[LVFBuffer alloc] initWithSize:3];
    _csgoGameBuffer = [[LVFBuffer alloc] initWithSize:5];
    NSLog(@"init delegate");
    
    
    
    
    

    
    //setup the login window
    NSRect winFrame = NSRectFromCGRect(CGRectMake(0, 0, 573, 335));
    NSUInteger stylemask = /*NSTexturedBackgroundWindowMask|*/NSClosableWindowMask|NSMiniaturizableWindowMask|NSTitledWindowMask/*|NSResizableWindowMask*/;
    loginWindow = [[NSWindow alloc] initWithContentRect:winFrame styleMask:stylemask backing:NSBackingStoreBuffered defer:YES];
    [loginWindow setReleasedWhenClosed:NO];
    [loginWindow center];
    
    
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
    NSRect regFrame = NSRectFromCGRect(CGRectMake(countryFrame.origin.x, 25, 220, 25));
    
    
    NSRect setSecretFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, regFrame.origin.y, mailFrame.size.width, mailFrame.size.height));
    NSRect setPassFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, setSecretFrame.origin.y+35, mailFrame.size.width, mailFrame.size.height));
    NSRect setDeviceFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x, setPassFrame.origin.y+35, mailFrame.size.width, mailFrame.size.height));
    
    
    NSLog(@"set frames");
    
    
    txtPassword = [[NSSecureTextField alloc] initWithFrame:passFrame];
    txtEmail = [[NSTextField alloc] initWithFrame:mailFrame];
    _txt1Secure = [[NSSecureTextField alloc] initWithFrame:mailFrame];
    _txt3Secure = [[NSSecureTextField alloc] initWithFrame:questionFrame];
    _txt2Insecure = [[NSTextField alloc] initWithFrame:passFrame];
    
    _btnSetPass  = [[NSButton alloc] initWithFrame:setPassFrame];
    _btnSetDeviceName = [[NSButton alloc] initWithFrame:setDeviceFrame];
    _btnSetSecret = [[NSButton alloc] initWithFrame:setSecretFrame];
    
    
    btnSignUp = [[NSButton alloc] initWithFrame:regFrame];
    btnLogin = [[NSButton alloc] initWithFrame:loginFrame];
    _btnQuestion = [[NSButton alloc] initWithFrame:questionBtnFrame];
    [[txtPassword cell] setPlaceholderString:@"Password"];
    [[txtEmail cell] setPlaceholderString:@"E-Mail"];
    [btnLogin setTitle:@"Log In"];
    [btnSignUp setTitle:@"Join GameQ"];
    [btnLogin setBezelStyle:NSRoundedBezelStyle];
    [_btnSetSecret setTitle:@"Change secret question"];
    [_btnSetPass setTitle:@"Change password"];
    [_btnSetDeviceName setTitle:@"Set device name"];
    [_btnSetDeviceName setBezelStyle:NSRoundedBezelStyle];
    [_btnSetPass setBezelStyle:NSRoundedBezelStyle];
    [_btnSetSecret setBezelStyle:NSRoundedBezelStyle];
    [_btnSetDeviceName setButtonType:NSMomentaryChangeButton];
    [_btnSetPass setButtonType:NSMomentaryChangeButton];
    [_btnSetSecret setButtonType:NSMomentaryChangeButton];
    [_btnSetSecret setTarget:self];
    [_btnSetPass setTarget:self];
    [_btnSetDeviceName setTarget:self];
    [_btnSetDeviceName setAction:@selector(setupSetDevice)];
    [_btnSetPass setAction:@selector(setupSetPass)];
    [_btnSetSecret setAction:@selector(setupSetSecret)];
    [_btnSetPass setBordered:NO];
    [_btnSetSecret setBordered:NO];
    [_btnSetDeviceName setBordered:NO];
    
    
    
    
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
    
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[btnSignUp attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [btnSignUp setAttributedTitle:colorTitle2];
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    
    
    
    
    
    
    [btnLogin setImage:[NSImage imageNamed:@"Red.png"]];
    [btnSignUp setImage:[NSImage imageNamed:@"Red.png"]];
    [_btnQuestion setImage:[NSImage imageNamed:@"Red.png"]];
    [_btnSetPass setImage:[NSImage imageNamed:@"Red.png"]];
    [_btnSetSecret setImage:[NSImage imageNamed:@"Red.png"]];
    [_btnSetDeviceName setImage:[NSImage imageNamed:@"Red.png"]];
    [btnLogin setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    [btnSignUp setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    [_btnQuestion setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    [_btnSetPass setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    [_btnSetSecret setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    [_btnSetDeviceName setAlternateImage:[NSImage imageNamed:@"HighRed.png"]];
    
    
   
    NSLog(@"set colors");

    
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
    
    
    NSRect aFrame = NSRectFromCGRect(CGRectMake(mailFrame.origin.x - 15, countryFrame.origin.y-30, 247, 300));
    NSImageView *aView = [[NSImageView alloc] initWithFrame:aFrame];
    [aView setImageScaling:NSImageScaleAxesIndependently];
    [aView setImage:[NSImage imageNamed:@"Gray.png"]];
    [loginWindow.contentView addSubview:aView];
    
    NSRect bFrame = NSRectFromCGRect(CGRectMake(winFrame.size.width/2 + 1.5, countryFrame.origin.y-30, 247, 300));
    /*NSImageView *bView = [[NSImageView alloc] initWithFrame:bFrame];
    [bView setImageScaling:NSImageScaleAxesIndependently];
    [bView setImage:[NSImage imageNamed:@"Gray.png"]];
    [loginWindow.contentView addSubview:bView];
    */
    //NSRect cFrame = NSRectFromCGRect(CGRectMake(bFrame.origin.x + (bFrame.size.width-256)/2, bFrame.origin.y + (bFrame.size.height-256)/2, 256, 256));
    NSRect cFrame = NSRectFromCGRect(CGRectMake((((winFrame.size.width-(aFrame.origin.x + aFrame.size.width))-256)/2) + aFrame.origin.x + aFrame.size.width, bFrame.origin.y + (bFrame.size.height-256)/2, 256, 256));
    NSImageView *cView = [[NSImageView alloc] initWithFrame:cFrame];
    [cView setImage:[NSImage imageNamed:@"NotificationLogo"]];
    [loginWindow.contentView addSubview:cView];
    
    
    
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
    [loginWindow.contentView addSubview:_btnSetDeviceName];
    [loginWindow.contentView addSubview:_btnSetSecret];
    [loginWindow.contentView addSubview:_btnSetPass];
    [loginWindow.contentView addSubview:_txt1Secure];
    [loginWindow.contentView addSubview:_txt2Insecure];
    [loginWindow.contentView addSubview:_txt3Secure];
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
    [_btnSetPass setAlphaValue:0];
    [_btnSetDeviceName setAlphaValue:0];
    [_btnSetSecret setAlphaValue:0];
    [_btnSetSecret setEnabled:NO];
    [_btnSetPass setEnabled:NO];
    [_btnSetDeviceName setEnabled:NO];
    [_txt1Secure setEnabled:NO];
    [_txt1Secure setHidden:YES];
    [_txt3Secure setEnabled:NO];
    [_txt3Secure setHidden:YES];
    [_txt2Insecure setEnabled:NO];
    [_txt2Insecure setHidden:YES];
    NSLog(@"added views");
    
    
    
    
    
    
    
    if ([_dataHandler getBolIsLoggedIn].boolValue) {
        [_connectionsHandler loginWithUser:[_dataHandler getEmail] andPass:[_dataHandler getPass]];
    } else {
        [self log:self];
    }
    [_connectionsHandler chkVersion];
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
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[btnSignUp attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [btnSignUp setAttributedTitle:colorTitle2];
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    
    sleep(0.3);
    [txtPassword setHidden:NO];
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
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[btnSignUp attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [btnSignUp setAttributedTitle:colorTitle2];
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    
    sleep(0.3);
    [txtPassword setHidden:NO];
    
}

-(void) setupLogin{
    
    [btnLogin setAction:@selector(attemptLogin)];
    [btnSignUp setAction:@selector(setupRegister)];
    [btnSignUp setTitle:@"Join GameQ"];
    [btnLogin setTitle:@"Log In"];
    [_btnQuestion setTitle:@"Forgot?"];
    [_btnQuestion setAction:@selector(setupQuestion)];
    [txtEmail.cell setPlaceholderString:@"E-Mail"];
    [txtPassword.cell setPlaceholderString:@"Password"];
    [_txtQuestion.cell setPlaceholderString:@"Secret Question"];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtPassword.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    [txtPassword setHidden:NO];
    [txtEmail setHidden:NO];
    [_txtQuestion setHidden:NO];
    [_txtAnswer setHidden:NO];
    
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
    [txtPassword setHidden:NO];
    [[txtEmail animator]setAlphaValue:1];
    [[txtEmail animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:1];
    [[btnSignUp animator]setEnabled:YES];
    [[btnLogin animator] setEnabled:YES];
    [[btnLogin animator] setAlphaValue:1];
    
    [_txt1Secure setEnabled:NO];
    [_txt1Secure setHidden:YES];
    [_txt3Secure setEnabled:NO];
    [_txt3Secure setHidden:YES];
    [_txt2Insecure setEnabled:NO];
    [_txt2Insecure setHidden:YES];
    
    [[_btnSetSecret animator]setEnabled:NO];
    [[_btnSetPass animator]setEnabled:NO];
    [[_btnSetDeviceName animator] setEnabled:NO];
    [[_btnSetDeviceName animator] setAlphaValue:0];
    [[_btnSetPass animator] setAlphaValue:0];
    [[_btnSetSecret animator] setAlphaValue:0];
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[btnSignUp attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [btnSignUp setAttributedTitle:colorTitle2];
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    
    
    
}

-(void) setupSettings{
    
    
    [btnLogin setTitle:@"OK"];
    [_btnQuestion setTitle:@"Cancel"];
    [_btnQuestion setAction:@selector(setupSettings)];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtEmail.frame.origin.y-35, 100, 25));
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
    [[_btnQuestion animator] setAlphaValue:0];
    [_btnQuestion setEnabled:NO];
    [[btnLogin animator] setEnabled:NO];
    [[btnLogin animator] setAlphaValue:0];
    [[txtPassword animator]setAlphaValue:0];
    [[txtPassword animator]setEnabled:NO];
    [[txtEmail animator]setAlphaValue:0];
    [[txtEmail animator]setEnabled:NO];
    [[btnSignUp animator]setAlphaValue:0];
    [[btnSignUp animator]setEnabled:NO];
    [_txt1Secure setEnabled:NO];
    [_txt3Secure setEnabled:NO];
    [_txt2Insecure setEnabled:NO];
    [_txt1Secure setAlphaValue:0];
    [_txt2Insecure setAlphaValue:0];
    [_txt3Secure setAlphaValue:0];
    
    [[_btnSetSecret animator]setEnabled:YES];
    [[_btnSetPass animator]setEnabled:YES];
    [[_btnSetDeviceName animator] setEnabled:YES];
    [[_btnSetDeviceName animator] setAlphaValue:1];
    [[_btnSetPass animator] setAlphaValue:1];
    [[_btnSetSecret animator] setAlphaValue:1];
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnSetDeviceName attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [_btnSetDeviceName setAttributedTitle:colorTitle2];
    
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    
    NSMutableAttributedString *colorTitle4 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnSetPass attributedTitle]];
    NSRange title4Range = NSMakeRange(0, [colorTitle4 length]);
    [colorTitle4 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title4Range];
    [_btnSetPass setAttributedTitle:colorTitle4];
    
    NSMutableAttributedString *colorTitle5 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnSetSecret attributedTitle]];
    NSRange title5Range = NSMakeRange(0, [colorTitle5 length]);
    [colorTitle5 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title5Range];
    [_btnSetSecret setAttributedTitle:colorTitle5];
    
    [self enableButtons];
    sleep(0.3f);
    [txtPassword setHidden:YES];
    [_txt3Secure setHidden:YES];
    [_txt2Insecure setHidden:YES];
    [_txt1Secure setHidden:YES];
    
}

-(void) setupSetSecret
{
    [btnLogin setAction:@selector(attemptSetSecret)];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, _txtQuestion.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    [_txt1Secure.cell setPlaceholderString:@"Password"];
    [_txt2Insecure.cell setPlaceholderString:@"New secret question"];
    [_txt3Secure.cell setPlaceholderString:@"New secret answer"];
    
    
    [_txt1Secure setStringValue:@""];
    [_txt2Insecure setStringValue:@""];
    [_txt3Secure setStringValue:@""];
    
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
    [[_btnQuestion animator] setEnabled:YES];
    [[btnLogin animator] setEnabled:YES];
    [[btnLogin animator] setAlphaValue:1];
    [[txtPassword animator]setAlphaValue:0];
    [[txtPassword animator]setEnabled:NO];
    [[txtEmail animator]setAlphaValue:0];
    [[txtEmail animator]setEnabled:NO];
    [[btnSignUp animator]setAlphaValue:0];
    [[btnSignUp animator]setEnabled:NO];
    
    [_txt3Secure setHidden:NO];
    [_txt2Insecure setHidden:NO];
    [_txt1Secure setHidden:NO];
    [_txt1Secure setEnabled:YES];
    [_txt3Secure setEnabled:YES];
    [_txt2Insecure setEnabled:YES];
    [[_txt1Secure animator] setAlphaValue:1];
    [[_txt2Insecure animator] setAlphaValue:1];
    [[_txt3Secure animator] setAlphaValue:1];
    
    [[_btnSetSecret animator]setEnabled:NO];
    [[_btnSetPass animator]setEnabled:YES];
    [[_btnSetDeviceName animator] setEnabled:YES];
    [[_btnSetDeviceName animator] setAlphaValue:1];
    [[_btnSetPass animator] setAlphaValue:1];
    [[_btnSetSecret animator] setAlphaValue:1];
    
    sleep(0.3f);
    [txtPassword setHidden:YES];
    [txtEmail setHidden:YES];
    [_txtQuestion setHidden:YES];
    [_txtAnswer setHidden:YES];
    
}

-(void) setupSetPass
{
    [btnLogin setAction:@selector(attemptSetPass)];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtPassword.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    [_txt1Secure.cell setPlaceholderString:@"Old password"];
    [txtPassword.cell setPlaceholderString:@"New password"];
    
    [_txt1Secure setStringValue:@""];
    [txtPassword setStringValue:@""];
    [txtPassword setHidden:NO];
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
    [[_btnQuestion animator] setEnabled:YES];
    [[btnLogin animator] setEnabled:YES];
    [[btnLogin animator] setAlphaValue:1];
    
    [txtPassword setHidden:NO];
    [[txtPassword animator]setAlphaValue:1];
    [[txtPassword animator]setEnabled:YES];
    [[txtEmail animator]setAlphaValue:1];
    [[txtEmail animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:0];
    [[btnSignUp animator]setEnabled:NO];
    
    [[_btnSetSecret animator]setEnabled:YES];
    [[_btnSetPass animator]setEnabled:NO];
    [[_btnSetDeviceName animator] setEnabled:YES];
    [[_btnSetDeviceName animator] setAlphaValue:1];
    [[_btnSetPass animator] setAlphaValue:1];
    [[_btnSetSecret animator] setAlphaValue:1];
    
    
    [_txt1Secure setHidden:NO];
    [_txt1Secure setEnabled:YES];
    [_txt3Secure setEnabled:NO];
    [_txt2Insecure setEnabled:NO];
    [[_txt1Secure animator] setAlphaValue:1];
    [[_txt2Insecure animator] setAlphaValue:0];
    [[_txt3Secure animator] setAlphaValue:0];
    
    sleep(0.3f);
    
    [txtEmail setHidden:YES];
    [_txtQuestion setHidden:YES];
    [_txtAnswer setHidden:YES];
    [_txt3Secure setHidden:YES];
    [_txt2Insecure setHidden:YES];
}

-(void) setupSetDevice
{
    [btnLogin setAction:@selector(attemptSetDevice)];
    NSRect loginFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x+_rolloverCountry.frame.size.width+20, txtEmail.frame.origin.y-35, 100, 25));
    NSRect questionBtnFrame = NSRectFromCGRect(CGRectMake(_rolloverCountry.frame.origin.x, loginFrame.origin.y, 100, 25));
    
    [txtEmail.cell setPlaceholderString:@"Device name"];
    [txtEmail setStringValue:_dataHandler.getDeviceID];
    [txtEmail setHidden:NO];
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
    [[_btnQuestion animator] setEnabled:YES];
    [[btnLogin animator] setEnabled:YES];
    [[btnLogin animator] setAlphaValue:1];
    [[txtPassword animator]setAlphaValue:0];
    [[txtPassword animator]setEnabled:NO];
    
    [[txtEmail animator]setAlphaValue:1];
    [[txtEmail animator]setEnabled:YES];
    [[btnSignUp animator]setAlphaValue:0];
    [[btnSignUp animator]setEnabled:NO];
    
    [[_btnSetSecret animator]setEnabled:YES];
    [[_btnSetPass animator]setEnabled:YES];
    [[_btnSetDeviceName animator] setEnabled:NO];
    [[_btnSetDeviceName animator] setAlphaValue:1];
    [[_btnSetPass animator] setAlphaValue:1];
    [[_btnSetSecret animator] setAlphaValue:1];
    
    
    [_txt1Secure setEnabled:NO];
    [_txt3Secure setEnabled:NO];
    [_txt2Insecure setEnabled:NO];
    [[_txt1Secure animator] setAlphaValue:0];
    [[_txt2Insecure animator] setAlphaValue:0];
    [[_txt3Secure animator] setAlphaValue:0];
    
    sleep(0.3f);
    [_txt1Secure setHidden:YES];
    [txtPassword setHidden:YES];
    [_txtQuestion setHidden:YES];
    [_txtAnswer setHidden:YES];
    [_txt3Secure setHidden:YES];
    [_txt2Insecure setHidden:YES];
}

-(void) attemptSetSecret
{
    //checks if any text exists in the fields
    if (![_txt1Secure.stringValue isEqual:@""] && ![_txt3Secure.stringValue isEqual:@""]) {
        if (_txt1Secure.stringValue.length > 5 && _txt3Secure.stringValue.length > 5) {
            if ([_txt1Secure.stringValue rangeOfString:@"\""].location == NSNotFound && [_txt2Insecure.stringValue rangeOfString:@"\""].location == NSNotFound &&
                [_txt1Secure.stringValue rangeOfString:@"\\"].location == NSNotFound && [_txt2Insecure.stringValue rangeOfString:@"\\"].location == NSNotFound && [_txt3Secure.stringValue rangeOfString:@"\""].location == NSNotFound &&
                [_txt3Secure.stringValue rangeOfString:@"\\"].location == NSNotFound) {
                //what we wanna do
                
                [self disableButtons];
                [_connectionsHandler postNewSecretQuestion:_txt2Insecure.stringValue andSecret:_txt3Secure.stringValue forEmail:_dataHandler.getEmail andPassword:_txt1Secure.stringValue];
                
                
                
            } else {
                [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified details contain illegal characters"] runModal];
            }
        } else {
            [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Password and secret must be a minimum of 6 characters"] runModal];
        }
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter valid details!"] runModal];
    }
}

-(void) attemptSetDevice
{
    //checks if any text exists in the fields
    if (![txtEmail.stringValue isEqual:@""]) {
        if ([txtEmail.stringValue rangeOfString:@"\""].location == NSNotFound &&
            [txtEmail.stringValue rangeOfString:@"\\"].location == NSNotFound) {
            //what we wanna do
            [_dataHandler setDeviceID:txtEmail.stringValue];
            [self disableButtons];
            [_connectionsHandler postNewDeviceName:txtEmail.stringValue forToken:_dataHandler.getToken andEmail:_dataHandler.getEmail];
        } else {
            [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified name contains illegal characters"] runModal];
        }
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter valid details!"] runModal];
    }
}

-(void) attemptSetPass
{
    //checks if any text exists in the fields
    if (![_txt1Secure.stringValue isEqual:@""] && ![txtPassword.stringValue isEqual:@""]) {
        if (_txt1Secure.stringValue.length > 5 && txtPassword.stringValue.length > 5) {
            if ([_txt1Secure.stringValue rangeOfString:@"\""].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\""].location == NSNotFound &&
                [_txt1Secure.stringValue rangeOfString:@"\\"].location == NSNotFound && [txtPassword.stringValue rangeOfString:@"\\"].location == NSNotFound) {
                //what we wanna do
                
                [self disableButtons];
                [_connectionsHandler postNewPassword:txtPassword.stringValue forEmail:_dataHandler.getEmail andOldPassword:_txt1Secure.stringValue];
                
                
                
            } else {
                [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"The specified details contain illegal characters"] runModal];
            }
        } else {
            [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Passwords must be a minimum of 6 characters"] runModal];
        }
    } else {
        [[NSAlert alertWithMessageText:@"Invalid details" defaultButton:@"OK" alternateButton:nil otherButton:nil informativeTextWithFormat:@"Please enter valid details!"] runModal];
    }
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
    
    
    
    
    
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
    NSMutableAttributedString *colorTitle2 = [[NSMutableAttributedString alloc] initWithAttributedString:[btnSignUp attributedTitle]];
    NSRange title2Range = NSMakeRange(0, [colorTitle2 length]);
    [colorTitle2 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title2Range];
    [btnSignUp setAttributedTitle:colorTitle2];
    
    NSMutableAttributedString *colorTitle3 = [[NSMutableAttributedString alloc] initWithAttributedString:[_btnQuestion attributedTitle]];
    NSRange title3Range = NSMakeRange(0, [colorTitle3 length]);
    [colorTitle3 addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:title3Range];
    [_btnQuestion setAttributedTitle:colorTitle3];
    sleep(0.3);
    [txtPassword setHidden:YES];
    
}
    
-(void) checkQuestion{
    [self disableButtons];
    [_connectionsHandler getSecretPost:txtEmail.stringValue];
    _strQuestionMail = [[NSString alloc] initWithFormat:@"%@", txtEmail.stringValue];
    
    
}
-(void) setupAnswerWithQuestion:(NSString*)question {
    [self enableButtons];
    
    [btnLogin setAction:@selector(validateQuestion)];
    _strQuestion = [[NSString alloc] initWithString:question];
    [txtEmail.cell setPlaceholderString:question];
    [btnLogin setTitle:@"OK"];
    
    NSMutableAttributedString *colorTitle = [[NSMutableAttributedString alloc] initWithAttributedString:[btnLogin attributedTitle]];
    NSRange titleRange = NSMakeRange(0, [colorTitle length]);
    [colorTitle addAttribute:NSForegroundColorAttributeName value:[NSColor whiteColor] range:titleRange];
    [btnLogin setAttributedTitle:colorTitle];
    
}

- (void) enableButtons
{
    [btnLogin setEnabled:YES];
    [btnSignUp setEnabled:YES];
    [_btnQuestion setEnabled:YES];
    [btnLog setEnabled:YES];
    [_btnSetDeviceName setEnabled:YES];
    [_btnSetPass setEnabled:YES];
    [_btnSetSecret setEnabled:YES];
    
}

- (void) disableButtons
{
    [btnLogin setEnabled:NO];
    [btnSignUp setEnabled:NO];
    [_btnQuestion setEnabled:NO];
    [btnLog setEnabled:NO];
    [_btnSetDeviceName setEnabled:NO];
    [_btnSetPass setEnabled:NO];
    [_btnSetSecret setEnabled:NO];
    
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
            int len = ntohs(ip->ip_len);
            len = len + 14; // to get full packet size
            NSLog(@"got packet and sending for analysis");
            [self analyzePacketWithSport:sport Dport:dport andWlen:len];
            NSLog(@"analysis done");
            
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
    

    
	
    
	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));
    
    
    
    return;
}

/*
 * print packet payload data (avoid printing binary data)
 */

void print_payload(const u_char *payload, int len)
{
    
	int len_rem = len;
	int line_width = 16;			// number of bytes per line
	int line_len;
	int offset = 0;					// zero-based offset counter
	const u_char *ch = payload;
    
	if (len <= 0)
		return;
    
	// data fits on one line
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}
    
	// data spans multiple lines
	for ( ;; ) {
		// compute current line length
		line_len = line_width % len_rem;
		// print line
		print_hex_ascii_line(ch, line_len, offset);
		// compute total remaining
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print
		ch = ch + line_len;
		// add offset
		offset = offset + line_width;
		// check if we have line width chars or less
		if (len_rem <= line_width) {
			// print last line and get out
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

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    
	int i;
	int gap;
	const u_char *ch;
    
	// offset
	printf("%05d   ", offset);
	
	// hex
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		// print extra space after 8th byte for visual aid
		if (i == 7)
			printf(" ");
	}
	// print space to handle line less than 8 bytes
	if (len < 8)
		printf(" ");
	
	// fill hex gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	// ascii (if printable)
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
        [_connectionsHandler monitorMeForEmail:_dataHandler.getEmail];
        NSLog(@"toggleOn");
    } else {
        [self toggleOff:nil];
        NSLog(@"toggleOff");
    }
    NSLog(@"arglar %@", [NSNumber numberWithBool:bolIsActive]);
    bolIsActive = !bolIsActive;
    NSLog(@"arglar %@", [NSNumber numberWithBool:bolIsActive]);
    
}

- (IBAction)showPrefs:(id)sender {
    
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToForegroundApplication);
    
    //[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    //[[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
    //[loginWindow makeKeyWindow];
    [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
    [self setupSettings];
    [loginWindow center];
    [loginWindow orderFrontRegardless];
    [loginWindow makeKeyAndOrderFront:nil];
    [self setupSetDevice];
    //[loginWindow orderFront:nil];
    NSLog(@"showing window");
    
    
}

- (IBAction)toggleOff:(id)sender {
    [btnToggleActive setTitle:@"Start Monitoring"];
    [self.statusBar setImage:[NSImage imageNamed:@"Qblack"]];
    [_btnStatus2 setTitle:@"Status: Not Tracking"];
    pcap_breakloop(handle);
    printf("\nCapture complete.\n");
    [self performSelectorOnMainThread:@selector(stopTimer) withObject:nil waitUntilDone:false];
    bolFirstTick = true;
    [self clearBuffers];
    [_connectionsHandler UpdateStatusWithGame:kNOGAME andStatus:[NSNumber numberWithInt:kNOTTRACKING] andToken:[_dataHandler getToken]];
    printf("\nCapture complete.\n");
    pcap_freecode(&fp);
    pcap_close(handle);
    
    
}

- (void) clearBuffers {
    
    [_csgoGameBuffer clear];
    [_csgoQBuffer clear];
    [_dota174Buffer clear];
    [_dota190Buffer clear];
    [_dota206Buffer clear];
    [_dotaCBuffer clear];
    [_dotaQBuffer clear];
    [_honQBuffer clear];
    
}

- (void) startMonitor
{
    [NSThread detachNewThreadSelector:@selector(toggleOn:) toTarget:self withObject:nil];
}

- (void) setupCap
{
    
     
    //pCap vars
    struct ifaddrs* interfaces = NULL;
    struct ifaddrs* temp_addr = NULL;
    
    
    
    
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
    NSLog(@"setting up cap");
    char *filter_exp = [_currentFilter UTF8String];
    //NSLog(@"new filter: %s", filter_exp);
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
    NSLog(@"set up cap");
    
    
}


- (NSString *) monitorExtract:(int)val
{
    NSString *a = [_monitorString substringToIndex:val];
    _monitorString = [_monitorString substringFromIndex:val];
    return  a;
}



- (void) handleGame:(NSString *)gameString
{
    
    NSLog(@"gamestring: %@", gameString);
    int game = [gameString substringToIndex:2].intValue;
    gameString = [gameString substringFromIndex:2];
    int cooldown = [gameString substringToIndex:2].intValue;
    gameString = [gameString substringFromIndex:2];
    int proclen = [gameString substringToIndex:4].intValue;
    gameString = [gameString substringFromIndex:4];
    NSString* proc = [gameString substringToIndex:proclen];
    gameString = [gameString substringFromIndex:proclen];
    int caplen = [gameString substringToIndex:4].intValue;
    gameString = [gameString substringFromIndex:4];
    NSString* capString = [gameString substringToIndex:caplen];
    gameString = [gameString substringFromIndex:caplen];
    
    [_coolers setObject:[NSNumber numberWithInt:cooldown] forKey:[NSNumber numberWithInt:game]];
    [_procs addObject:[[LVFCompartment alloc] initWithName:[NSNumber numberWithInt:game] andObject:proc]];
    [self handleCap:capString];
    
    int numStats = [gameString substringToIndex:3].intValue;
    gameString = [gameString substringFromIndex:3];
    NSLog(@"%@", gameString);
    for (int i = 0; i < numStats; i++) {
        NSLog(@"%@", gameString);
        int statlen = [gameString substringToIndex:4].intValue;
        gameString = [gameString substringFromIndex:4];
        NSString *state = [gameString substringToIndex:statlen];
        gameString = [gameString substringFromIndex:statlen];
        [self handleState:state forGame:game andState:i];
        //NSLog(@"state: %@", state);
    }
}

- (void) handleState:(NSString *)stateString forGame:(int)game andState:(int)state
{
    int numOrs = [stateString substringToIndex:3].intValue;
    stateString = [stateString substringFromIndex:3];
    for (int i = 0; i < numOrs; i++) {
        
        BOOL special = [stateString substringToIndex:1].intValue;
        stateString = [stateString substringFromIndex:1];
        int numCons = [stateString substringToIndex:3].intValue;
        stateString = [stateString substringFromIndex:3];
        NSMutableDictionary *conditions = [[NSMutableDictionary alloc] init];
        NSMutableDictionary *waits = [[NSMutableDictionary alloc] init];
        NSMutableDictionary *nots = [[NSMutableDictionary alloc] init];
        for (int j = 0; j < numCons; j++) {
            BOOL bolnot = [stateString substringToIndex:1].boolValue;
            stateString = [stateString substringFromIndex:1];
            int waittime = [stateString substringToIndex:2].intValue;
            stateString = [stateString substringFromIndex:2];
            int numPacks = [stateString substringToIndex:3].intValue;
            stateString = [stateString substringFromIndex:3];
            int nameLen = [stateString substringToIndex:4].intValue;
            stateString = [stateString substringFromIndex:4];
            NSString* packName = [stateString substringToIndex:nameLen];
            stateString = [stateString substringFromIndex:nameLen];
            
            [conditions setObject:[NSNumber numberWithInt:numPacks] forKey:packName];
            [waits setObject:[NSNumber numberWithInt:waittime] forKey:packName];
            [nots setObject:[NSNumber numberWithBool:bolnot] forKey:packName];
            
            
        }
        LVFState *tmpStat = [[LVFState alloc] initWithConditions:conditions andWaitTimes:waits andNots:nots andGame:[NSNumber numberWithInt:game] andState:[NSNumber numberWithInt:state] forDelegate:self isSpecial:special];
        [_states addObject:tmpStat];
        
    }
}

- (void) handleCap:(NSString*)capString
{
    
    NSLog(@"cap handlin':");
    int numCaps = [capString substringToIndex:3].intValue;
    //NSLog(@"%d", numCaps);
    capString = [capString substringFromIndex:3];
    for (int i = 0; i < numCaps; i++) {
        //NSLog(@"another cap licks the dust");
        int nameLen = [capString substringToIndex:4].intValue;
        capString = [capString substringFromIndex:4];
        //NSLog(@"%@", capString);
        NSString *name = [capString substringToIndex:nameLen];
        capString = [capString substringFromIndex:nameLen];
        //NSLog(@"%@", capString);
        int buffSiz = [capString substringToIndex:2].intValue;
        capString = [capString substringFromIndex:2];
        //NSLog(@"%@", capString);
        int minSport = [capString substringToIndex:5].intValue;
        capString = [capString substringFromIndex:5];
        //NSLog(@"%@", capString);
        int maxSport = [capString substringToIndex:5].intValue;
        capString = [capString substringFromIndex:5];
        //NSLog(@"%@", capString);
        int minDport = [capString substringToIndex:5].intValue;
        capString = [capString substringFromIndex:5];
        //NSLog(@"%@", capString);
        int maxDport = [capString substringToIndex:5].intValue;
        capString = [capString substringFromIndex:5];
        //NSLog(@"%@", capString);
        int minWlen = [capString substringToIndex:4].intValue;
        capString = [capString substringFromIndex:4];
        //NSLog(@"%@", capString);
        int maxWlen = [capString substringToIndex:4].intValue;
        capString = [capString substringFromIndex:4];
        
        LVFCapObj *capobj = [[LVFCapObj alloc] initWithDelegate:self andName:name andMinSport:minSport andMaxSport:maxSport andMinDport:minDport andMaxDport:maxDport andMinWlen:minWlen andMaxWlen:maxWlen andBuffSize:buffSiz];
        if (capString.length >= 2) {
            if ([[capString substringToIndex:2] isEqualToString:@"<<"]) {
                capString = [capString substringFromIndex:2];
                int numComps = [capString substringToIndex:3].intValue;
                capString = [capString substringFromIndex:3];
                for (int j = 0; j<numComps; j++) {
                    
                    
                    int numPacks = [capString substringToIndex:3].intValue;
                    capString = [capString substringFromIndex:3];
                    int nLen = [capString substringToIndex:4].intValue;
                    capString = [capString substringFromIndex:4];
                    NSString *packName = [capString substringToIndex:nLen];
                    capString = [capString substringFromIndex:nLen];
                    
                    [capobj addComparisonForName:packName andValue:numPacks];
                    
                    
                }
            }
        }
        
        NSLog(@"adding capobj");
        [_capObjs addObject:capobj];
        
        
    }
    NSLog(@"cap handled" );
    
    
}

- (void) analyzePacketWithSport:(int)sport Dport:(int)dport andWlen:(int)wlen
{
    //NSLog(@"analyzing");
    for (LVFCapObj* obj in _capObjs) {
        //NSLog(@"analyzing with capobj:::");
        [obj checkPacketWithSport:sport andDport:dport andWlen:wlen];
    }
}

- (IBAction)toggleOn:(id)sender {
    NSLog(@"togglin On");
    
    _capObjs = [[NSMutableArray alloc] init];
    _buffers = [[NSMutableDictionary alloc] init];
    _prebuffers = [[NSMutableDictionary alloc] init];
    _states = [[NSMutableArray alloc] init];
    _coolers = [[NSMutableDictionary alloc] init];
    _procs = [[NSMutableArray alloc] init];
    //NSLog(@"money: %@", _monitorString);
    int flen = [self monitorExtract:4].intValue;
    _currentFilter = [self monitorExtract:flen];
    //NSLog(@"new filly: %@", _currentFilter);
    [self setupCap];
    _totalGames = [self monitorExtract:2].intValue;
    int numGames = [self monitorExtract:2].intValue;
    for (int i = 0; i<numGames; i++) {
        int glen = [self monitorExtract:4].intValue;
        NSString* game = [self monitorExtract:glen];
        //NSLog(@"kuk:  %@", game);
        //NSLog(@"kuk:  %@", _monitorString);
        [self handleGame:game];
    }
    
    _bolInGameArray = [[NSMutableArray alloc] init];
    _bolOnlineArray = [[NSMutableArray alloc] init];
    _bolpushArray = [[NSMutableArray alloc] init];
    _bolInGameArrayLast = [[NSMutableArray alloc] init];
    _bolOnlineArrayLast = [[NSMutableArray alloc] init];
    _bolpushArrayLast = [[NSMutableArray alloc] init];
    for (int j = 0; j<=_totalGames ; j++) {
        [_bolInGameArray insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [_bolOnlineArray insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [_bolpushArray insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [_bolInGameArrayLast insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [_bolOnlineArrayLast insertObject:[NSNumber numberWithBool:NO] atIndex:j];
        [_bolpushArrayLast insertObject:[NSNumber numberWithBool:NO] atIndex:j];
    }
    
    
    
    
    
    
    [_btnStatus2 setTitle:@"Status: Tracking"];
    printf("\nCapture started.\n");
    [self performSelectorOnMainThread:@selector(startTimer) withObject:nil waitUntilDone:false];
    [btnToggleActive setTitle:@"Stop Monitoring"];
    printf("\nCapture started.\n");
    [self.statusBar setImage:[NSImage imageNamed:@"Qblue"]];
    //TODO
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
        /*[_dataHandler setToken:@"none"];
        [_dataHandler setEmail:NULL];
        [_dataHandler setPass:NULL];
        */
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
    unsigned char * tag = main2();
    
    NSMutableString * result = [[NSMutableString alloc] init];
    ///    convert  --   char[] -> Nsstring in Hex format
    
    for (int i=0; i<6; i++) {
        [result appendString:[NSString stringWithFormat:@"%02x",tag[i]]];
    }
    
    NSLog(@"result :%@",result);
    
    
    NSString *tmpTag = [NSString stringWithFormat:@"%02x:%02x:%02x:%02x:%02x:%02x",tag[0],tag[1],tag[2],tag[3],tag[4],tag[5]];
    
    if (![[_dataHandler getFirstLog] isEqualToString:@"banana"]) {
        //first launch
        
        NSString *tmpUniqueID = [NSString stringWithFormat:@":%d", arc4random_uniform(RAND_MAX)];
        [_dataHandler setUniqueID:tmpUniqueID];
        [_dataHandler setFirstLog:@"banana"];
    }
    NSString *myTag = [NSString stringWithFormat:@"mac:%@:%@:%@",_dataHandler.getEmail, _dataHandler.getUniqueID, tmpTag];
    [_dataHandler setToken:myTag];
    //NSLog(@"%@", tmpTag);
    //NSLog(@"set token: %@", myTag);
    
    [_connectionsHandler.gqConnect postNow:[NSString stringWithFormat:@"token=%@&deviceName=%@&email=%@", [_dataHandler getToken], [_dataHandler getDeviceID], [_dataHandler getEmail]] to:updateTokenURL];
    //NSLog(@"token posted with token:%@ devName:%@ and email:%@", [_dataHandler getToken], [_dataHandler getDeviceID], [_dataHandler getEmail]);
    [btnLog setTitle:@"Change user"];
    [btnToggleActive setEnabled:true];
    bolLoggedIn = YES;
    [_dataHandler setBolIsLoggedIn:[NSNumber numberWithBool:YES]];
    if (![txtEmail.stringValue isEqualToString:@""] && ![txtPassword.stringValue isEqualToString:@""]) {
        [_dataHandler setEmail:txtEmail.stringValue];
        [_dataHandler setPass:txtPassword.stringValue];
    }
    [txtPassword setStringValue:@""];
    [_btnStatus setTitle:[NSString stringWithFormat:@"%@", [_dataHandler getEmail]]];
    [_btnStatus2 setTitle:@"Status: Online"];
    [_btnStatus setHidden:NO];
    [_btnPrefs setHidden:NO];
    [_btnPrefs setEnabled:YES];
    bolIsActive = NO;
    [self toggle:nil];
    [self.statusBar setImage:[NSImage imageNamed:@"Qblue"]];
    // following tells the server the client is online but no games have been launched
    [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:kNOGAME] andStatus:[NSNumber numberWithInt:kOFFLINE] andToken:[_dataHandler getToken]];
    [self setupLoggedIn];
    [_connectionsHandler checkPhones:_dataHandler.getEmail];
    
    
    
}



- (void) setDisconnected
{
    [txtEmail setStringValue:[_dataHandler getEmail]];
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
    [_btnPrefs setHidden:YES];
    [_btnPrefs setEnabled:NO];
    [_btnStatus2 setTitle:@"Status: Offline"];
    [_upTimeTimer invalidate];
    
    ProcessSerialNumber psn = { 0, kCurrentProcess };
    TransformProcessType(&psn, kProcessTransformToForegroundApplication);
    [[NSApplication sharedApplication] activateIgnoringOtherApps:YES];
    [self setupLogin];
    [loginWindow center];
    [loginWindow orderFrontRegardless];
    [loginWindow makeKeyAndOrderFront:nil];
}






// quits the app
- (IBAction)quit:(id)sender {
    if (bolIsActive) {
        [self toggleOff:(nil)];
    }
    [_connectionsHandler quitPostFromToken:[_dataHandler getToken]];
    exit(0);
    
}

//what happens on tack? (quick timer)
- (IBAction)tack:(id)sender {
    
    //NSLog(@"tick");
    
    
    
    
    
    // get processes
    NSString *output = [NSString string];
    for (NSRunningApplication *app in
         [[NSWorkspace sharedWorkspace] runningApplications]) {
        output = [output stringByAppendingFormat:@"%@\n",
                  [app localizedName] /*absoluteString*/];
    }
    
    
    
    
    
    NSMutableDictionary *tempPreBuff = [_prebuffers copy];
    NSLog(@"prebuff loop");
    for (NSString* key in tempPreBuff) {
        //NSLog(@"prebuff loop");
        NSLog(@"%@", key);
        int buffOld = [[tempPreBuff objectForKey:key] intValue];
        LVFBuffer* buffNew = [_buffers objectForKey:key];
        
        [buffNew increment:buffOld];
        [_buffers setObject:buffNew forKey:key];
        NSLog(@"buffVal: %d key: %@", ((LVFBuffer*)[_buffers objectForKey:key]).bufferValue , key);
        [_prebuffers setObject:[NSNumber numberWithInt:0] forKey:key];
        
    }
    
    for (int j = 0; j<=_totalGames ; j++) {
        [_bolInGameArray replaceObjectAtIndex:j withObject:[NSNumber numberWithBool:NO]];
        [_bolOnlineArray replaceObjectAtIndex:j withObject:[NSNumber numberWithBool:NO]];
        [_bolpushArray replaceObjectAtIndex:j withObject:[NSNumber numberWithBool:NO]];
    }
    
    for (LVFState* stat in _states) {
        NSLog(@"state: %@, game:%@, special:%d", stat.state, stat.game, stat.special);
        LVFState *aStat = [stat checkState];
        if (aStat != NULL) {
            NSLog(@"state not null");
            if (aStat.state.intValue == kINGAME_FOR_LVFSTATE) {
                NSLog(@"setting ingame");
                [_bolInGameArray replaceObjectAtIndex:aStat.game.intValue withObject:[NSNumber numberWithBool:YES]];
            } else if (aStat.state.intValue == kPUSH_FOR_LVFSTATE){
                NSLog(@"setting online");
                [_bolpushArray replaceObjectAtIndex:aStat.game.intValue withObject:[NSNumber numberWithBool:YES]];
            }
        }
        
    }
    for (NSNumber* key in _wildCards) {
        LVFState* aStat = [_wildCards objectForKey:key];
        NSLog(@"state not null");
        if (aStat.state.intValue == kINGAME_FOR_LVFSTATE) {
            NSLog(@"setting ingame from wild");
            [_bolInGameArray replaceObjectAtIndex:aStat.game.intValue withObject:[NSNumber numberWithBool:YES]];
        } else if (aStat.state.intValue == kPUSH_FOR_LVFSTATE){
            NSLog(@"setting online from wild");
            [_bolpushArray replaceObjectAtIndex:aStat.game.intValue withObject:[NSNumber numberWithBool:YES]];
        }
    }
    
    
    for (LVFCompartment* comp in _procs) {
        NSNumber *gameNum = (NSNumber *) comp.name;
        NSString *procName = (NSString *) comp.heldObject;
        if (!([output rangeOfString:procName].location == NSNotFound)) {
            [_bolOnlineArray replaceObjectAtIndex:gameNum.intValue withObject:[NSNumber numberWithBool:YES]];
        }
        
    }
    
    for (int i = 0; i <= _totalGames; i++) {
        NSNumber *pusher = [_bolpushArray objectAtIndex:i];
        NSNumber *online = [_bolOnlineArray objectAtIndex:i];
        NSLog(@"will it push?");
        if (pusher.boolValue) {
            if (online.boolValue) {
                NSLog(@"pushing %d", i);
                [self queuePopIfNotInGame:i];
                [_bolpushArrayLast replaceObjectAtIndex:i withObject:[NSNumber numberWithBool:YES]];
                NSNumber *cooldown = [_coolers objectForKey:[NSNumber numberWithInt:i]];
                _bolSpecialCD = true;
                if (_specialCooldownTimer != NULL) {
                    [_specialCooldownTimer invalidate];
                }
                _specialCooldownTimer = [NSTimer timerWithTimeInterval:cooldown.intValue target:self selector:@selector(resetSpecialCD) userInfo:nil repeats:NO];
                [[NSRunLoop mainRunLoop] addTimer:_specialCooldownTimer forMode:NSDefaultRunLoopMode];
            } else {
                [_bolpushArrayLast replaceObjectAtIndex:i withObject:[NSNumber numberWithBool:NO]];
            }
            
        }
    }
    //NSLog(@"totalgames:");
    for (int i = 0; i <= _totalGames; i++) {
        NSNumber *ingame = [_bolInGameArray objectAtIndex:i];
        NSNumber *online = [_bolOnlineArray objectAtIndex:i];
        if (ingame.boolValue && online.boolValue) {
            //NSLog(@"inng:");
            [self inGame:i];
        } else if (online.boolValue) {
            //NSLog(@"onnl:");
            [self online:i];
        } else {
            [self offline:i];
           // NSLog(@"offl:");
        }
        
    }
    
    
    
    bolFirstTick = 0;
    //NSLog(@"");
}

// slow buffer timer
- (IBAction)tick:(id)sender {
    
}





// handles offline state
- (IBAction)offline:(int)game {
    for (NSNumber *numberobject in _bolInGameArray) {
        if (numberobject.boolValue == true) {
            return;
        }
    }
    for (NSNumber *numberobject in _bolOnlineArray) {
        if (numberobject.boolValue == true) {
            return;
        }
    }
    //NSLog(@"called method \"offline\"");
    NSNumber *onlineBefore = [_bolOnlineArrayLast objectAtIndex:game];
    if (!onlineBefore.boolValue) {
        // do nothing if status was already offline, (initialized to offline)
    } else {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kOFFLINE] andToken:[_dataHandler getToken]];
    }
    [_bolOnlineArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
    [_bolInGameArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
    
    
}

//called whenever online status is detected
- (IBAction)online:(int)game {
    if (_bolQueueCD) {
        //NSLog(@"return1");
        return;
    }
    bool bolWasInGame = [[_bolInGameArrayLast objectAtIndex:game] boolValue];
    for (NSNumber *numberobject in _bolInGameArray) {
        if (numberobject.boolValue == true) {
            NSLog(@"return2");
            return;
        }
    }
    
    //NSLog(@"called method \"online\"");
    if ([[_bolOnlineArrayLast objectAtIndex:game] boolValue] && !bolWasInGame) {
        // do nothing if status already online, (initialized to offline)
    } else {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kONLINE] andToken:[_dataHandler getToken]];
        
    }
    [_bolOnlineArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    [_bolInGameArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:NO]];
    
}

//executes every quick timer user is in a match
- (IBAction)inGame:(int)game {
    
   // NSLog(@"called method \"ingame\"");
    
        
    if([[_bolInGameArrayLast objectAtIndex:game] boolValue]){
        //do nothing
        //NSLog(@"already ingame- do nothing");
        
    } else if(![[_bolInGameArray objectAtIndex:game] boolValue]) {
        [_connectionsHandler UpdateStatusWithGame:[NSNumber numberWithInt:game] andStatus:[NSNumber numberWithInt:kINGAME] andToken:[_dataHandler getToken]];
        //NSLog(@"became ingame- softpushing");
    }
    [_bolOnlineArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    [_bolInGameArrayLast replaceObjectAtIndex:game withObject:[NSNumber numberWithBool:YES]];
    _bolQueueCD = true;
    if (_queuePopCooldownTimer != NULL) {
        [_queuePopCooldownTimer invalidate];
    }
    _queuePopCooldownTimer = [NSTimer timerWithTimeInterval:5 target:self selector:@selector(resetQueueCooldown) userInfo:nil repeats:NO];
    [[NSRunLoop mainRunLoop] addTimer:_queuePopCooldownTimer forMode:NSDefaultRunLoopMode];
}

- (IBAction)queuePopIfNotInGame:(int)game {
    NSLog(@"pushing?");
    if (_bolQueueCD) {
        return;
    }
    NSLog(@"pushing????");
    //NSLog(@"called method \"queuePop\"");
    if([[_bolInGameArrayLast objectAtIndex:game] boolValue]){
        //do nothing
        NSLog(@"push- aborted, already in game");
    } else if(![[_bolInGameArrayLast objectAtIndex:game] boolValue]) {
        [_connectionsHandler pushNotificationForGame:[NSNumber numberWithInt:game] andToken:[_dataHandler getToken] andEmail:[_dataHandler getEmail]];
        NSLog(@"pushing!");
    }
    _bolQueueCD = true;
    if (_queuePopCooldownTimer != NULL) {
        [_queuePopCooldownTimer invalidate];
    }
    _queuePopCooldownTimer = [NSTimer timerWithTimeInterval:5 target:self selector:@selector(resetQueueCooldown) userInfo:nil repeats:NO];
    [[NSRunLoop mainRunLoop] addTimer:_queuePopCooldownTimer forMode:NSDefaultRunLoopMode];
    
    
    
    
    
}

- (void) resetQueueCooldown
{
    [_queuePopCooldownTimer invalidate];
    _bolQueueCD = false;
}

- (void) resetSpecialCD
{
    
    [_specialCooldownTimer invalidate];
    _bolSpecialCD = false;
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
    //printf("Incrementing HonQPack");
    honQPack++;
}

- (IBAction)incrementDotaQPack {
    //printf("Incrementing DotaQPack");
    dotaQPack++;
}

- (IBAction)incrementDota174Pack {
    //printf("Incrementing Dota174Pack");
    dota174Pack++;
}

- (IBAction)incrementDota190Pack {
    //printf("Incrementing Dota190Pack");
    dota190Pack++;
}

- (IBAction)incrementDota206Pack {
    //printf("Incrementing Dota206Pack");
    dota206Pack++;
}

- (IBAction)incrementDotaCPack {
    //printf("Incrementing DotaCPack");
    dotaCPack++;
}

- (IBAction)incrementcsgoQPack {
    //printf("Incrementing csgoQPack");
    csgoQPack++;
}

- (IBAction)incrementcsgoGamePack {
    //printf("Incrementing csgoGamePack");
    csgoGamePack++;
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
