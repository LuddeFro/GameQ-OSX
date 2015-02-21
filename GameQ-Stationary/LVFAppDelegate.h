//
//  LVFAppDelegate.h
//  testtest
//
//  Created by Ludvig Fröberg on 10/24/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <CoreGraphics/CoreGraphics.h>
#include "LVFpCap.h"
#include "netinet/in.h"
#include <stdio.h>
#include <ifaddrs.h>
#include "arpa/inet.h"
#include "pcap.h"
#import "LVFConnections.h"
#import "LVFDefinitions.h"
#import "LVFDataModel.h"
#import "LVFBuffer.h"
#import "LVFWindowHandler.h"
#import "LVFWindowViewSubclass.h"
#import <ServiceManagement/ServiceManagement.h>
#import "LVFCompartment.h"
#import "LVFState.h"
#import "LVFCapObj.h"
@class LVFBuffer;
@class LVFConnections;
@class LVFDataModel;

@interface LVFAppDelegate : NSObject <NSApplicationDelegate>


    

@property NSMutableDictionary *wildCards;

@property NSMutableArray *capObjs;
@property NSMutableDictionary *buffers;
@property NSMutableDictionary *prebuffers;
@property NSMutableArray *states;
@property NSMutableDictionary *coolers;
@property NSMutableArray *procs;
@property NSMutableString *monitorString;
@property NSString *currentFilter;
@property int totalGames;
- (void) analyzePacketWithSport:(int)sport Dport:(int)dport andWlen:(int)wlen;

@property NSMutableArray *bolInGameArray;
@property NSMutableArray *bolOnlineArray;
@property NSMutableArray *bolpushArray;

@property NSMutableArray *bolInGameArrayLast;
@property NSMutableArray *bolOnlineArrayLast;
@property NSMutableArray *bolpushArrayLast;
@property (strong, nonatomic) NSTimer *specialCooldownTimer;










@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;



@property BOOL bolQueueCD;
@property BOOL bolSpecialCD;
@property (strong) LVFWindowHandler *windowHandler;
@property (weak) IBOutlet NSMenu *mainMenu;
@property (strong, nonatomic) NSStatusItem *statusBar;
@property (weak) IBOutlet NSMenuItem *btnStatus;
@property (weak) IBOutlet NSMenuItem *btnStatus2;
@property (weak) IBOutlet NSMenuItem *btnToggleActive;
@property (weak) IBOutlet NSMenuItem *btnPrefs;
@property (weak) IBOutlet NSMenuItem *btnLog;
@property (weak) IBOutlet NSMenuItem *btnQuitApp;
@property (strong, nonatomic) NSTimer *countdownQuickTimer;
@property (strong, nonatomic) NSTimer *countdownSlowTimer;
@property (strong, nonatomic) NSTimer *upTimeTimer;
@property (strong, nonatomic) NSTimer *queuePopCooldownTimer;
@property int honQPack;
@property int dotaQPack;
@property int dota174Pack;
@property int dota190Pack;
@property int dota206Pack;
@property int dotaCPack;
@property int csgoQPack;
@property int csgoGamePack;



@property BOOL bolFirstTick;
@property LVFConnections *connectionsHandler;
@property (strong, nonatomic) NSWindow *loginWindow;
@property NSButton *btnSignUp;
@property NSTextField *txtEmail;
@property NSSecureTextField *txtPassword;
@property NSButton *btnLogin;
@property bool bolLoggedIn;
@property BOOL bolIsActive;
@property (strong, nonatomic) LVFDataModel *dataHandler;
@property NSTextField *txtFirstName;
@property NSTextField *txtLastName;
@property NSTextField *txtYOB;
@property NSTextField *txtQuestion;
@property NSTextField *txtAnswer;
@property NSSegmentedControl *segSex;

@property NSSecureTextField *txt1Secure;
@property NSSecureTextField *txt3Secure;
@property NSTextField *txt2Insecure;

@property NSPopUpButton *rolloverCountry;
    @property NSButton *btnQuestion;
    @property NSString *strQuestionMail;
    @property NSString *strQuestion;

@property NSButton *btnSetPass;
@property NSButton *btnSetSecret;
@property NSButton *btnSetDeviceName;
    
@property NSString *tmpDevName;

@property LVFBuffer *dotaQBuffer;
@property LVFBuffer *dota174Buffer;
@property LVFBuffer *dota190Buffer;
@property LVFBuffer *dota206Buffer;
@property LVFBuffer *dotaCBuffer;
@property LVFBuffer *honQBuffer;
@property LVFBuffer *csgoQBuffer;
@property LVFBuffer *csgoGameBuffer;


- (void)disableButtons;
- (void)enableButtons;

static void got_packet(id args, const struct pcap_pkthdr *header, const u_char *packet);
- (IBAction) toggle:(id)sender;
- (IBAction)showPrefs:(id)sender;
- (IBAction) log:(id)sender;
- (IBAction) quit:(id)sender;
- (void) setConnected;
- (void) setDisconnected;
- (void) setupLogin;
- (void) setupAnswerWithQuestion:(NSString*)question;
- (void) tearDownLoggedIn;
- (void) setupLoggedIn;
- (void) setupSettings;

- (IBAction)incrementHonQPack;
- (IBAction)incrementDotaQPack;
- (IBAction)incrementDota174Pack;
- (IBAction)incrementDota190Pack;
- (IBAction)incrementDota206Pack;
- (IBAction)incrementDotaCPack;
- (IBAction)incrementcsgoQPack;
- (void) startMonitor;










@end
