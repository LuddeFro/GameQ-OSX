//
//  LVFCapObj.h
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Foundation/NSLock.h>
#import "LVFAppDelegate.h"
#import "LVFCompartment.h"
#import "LVFBuffer.h"

@class LVFAppDelegate;

@interface LVFCapObj : NSObject

@property int minsport;
@property int maxsport;
@property int mindport;
@property int maxdport;
@property int minwlen;
@property int maxwlen;
@property NSString* name;
@property NSMutableDictionary* comparisons;
@property LVFAppDelegate* appDel;


//increments prebuffers for name if true with comparisons and instance variables
- (void) checkPacketWithSport:(int)sport andDport:(int)dport andWlen:(int)wlen;

//adds item to
- (void) addComparisonForName:(NSString *)name andValue:(int)value;

//initiation
- (id) initWithDelegate:(LVFAppDelegate *)del andName:(NSString *)name andMinSport:(int)minsport andMaxSport:(int)maxsport andMinDport:(int)mindport andMaxDport:(int)maxdport andMinWlen:(int)minwlen andMaxWlen:(int)maxwlen andBuffSize:(int)buffSize;


@end
