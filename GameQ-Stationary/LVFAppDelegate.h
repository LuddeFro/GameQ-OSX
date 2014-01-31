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

@class LVFBuffer;
@class LVFConnections;
@class LVFDataModel;

@interface LVFAppDelegate : NSObject <NSApplicationDelegate>


    
    
@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;




@property (strong) LVFWindowHandler *windowHandler;
@property (weak) IBOutlet NSMenu *mainMenu;
@property (strong, nonatomic) NSStatusItem *statusBar;
@property (weak) IBOutlet NSMenuItem *btnStatus;
@property (weak) IBOutlet NSMenuItem *btnStatus2;
@property (weak) IBOutlet NSMenuItem *btnToggleActive;
@property (weak) IBOutlet NSMenuItem *btnLog;
@property (weak) IBOutlet NSMenuItem *btnQuitApp;
@property (strong, nonatomic) NSTimer *countdownQuickTimer;
@property (strong, nonatomic) NSTimer *countdownSlowTimer;
@property int honQPack;
@property int dotaQPack;
@property int dotaCPack;
@property int csgoQPack;

@property NSMutableArray *bolInGameArray;
@property NSMutableArray *bolOnlineArray;


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
@property NSPopUpButton *rolloverCountry;
    @property NSButton *btnQuestion;
    @property NSString *strQuestionMail;
    @property NSString *strQuestion;
    


@property LVFBuffer *dotaQBuffer;




static void got_packet(id args, const struct pcap_pkthdr *header, const u_char *packet);
- (IBAction) toggle:(id)sender;
- (IBAction) log:(id)sender;
- (IBAction) quit:(id)sender;
- (void) setConnected;
- (void) setDisconnected;
- (void) setupLogin;
- (void) setupAnswerWithQuestion:(NSString*)question;

@end
