//
//  LVFAppDelegate.h
//  testtest
//
//  Created by Ludvig Fröberg on 10/24/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#include "LVFpCap.h"
#include "netinet/in.h"
#include <stdio.h>
#include <ifaddrs.h>
#include "arpa/inet.h"
#include "pcap.h"
#import "LVFConnections.h"
#import "LVFDefinitions.h"
#import "LVFDataModel.h"
@class LVFConnections;
@class LVFDataModel;

@interface LVFAppDelegate : NSObject <NSApplicationDelegate>


@property (assign) IBOutlet NSWindow *window;

@property (readonly, strong, nonatomic) NSPersistentStoreCoordinator *persistentStoreCoordinator;
@property (readonly, strong, nonatomic) NSManagedObjectModel *managedObjectModel;
@property (readonly, strong, nonatomic) NSManagedObjectContext *managedObjectContext;

- (IBAction)saveAction:(id)sender;





@property (weak) IBOutlet NSMenu *mainMenu;
@property (strong, nonatomic) NSStatusItem *statusBar;
@property (weak) IBOutlet NSMenuItem *btnStatus;
@property (weak) IBOutlet NSMenuItem *btnStatus2;
@property (weak) IBOutlet NSMenuItem *btnToggleActive;
@property (weak) IBOutlet NSMenuItem *btnLog;
@property (weak) IBOutlet NSMenuItem *btnQuitApp;
@property (strong, nonatomic) NSTimer *countdownTimer;
@property (strong, nonatomic) NSTimer *countdownQuickTimer;
@property int honQPack;
@property int honCPack;
@property BOOL bolInGame;
@property BOOL bolOnline;
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




static void got_packet(id args, const struct pcap_pkthdr *header, const u_char *packet);
- (IBAction) toggle:(id)sender;
- (IBAction) log:(id)sender;
- (IBAction) quit:(id)sender;
- (void) setConnected;
- (void) setDisconnected;

@end
