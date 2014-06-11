//
//  LVFResponses.h
//  NetMonitor
//
//  Created by Ludvig Fröberg on 10/19/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "LVFConnections.h"
#import "LVFAppDelegate.h"
#import "LVFDataModel.h"

@class LVFConnections;

@interface LVFConnect : NSObject

@property NSString *shortTermMemory;


- (void)postNow:(NSString *)toPost to:(NSString *)link;
- (id) initWithDelegate:(LVFConnections *)del;
- (void) connectionAlert:(NSString*)code;
@end
