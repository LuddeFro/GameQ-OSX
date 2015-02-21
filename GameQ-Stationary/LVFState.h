//
//  LVFState.h
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "LVFAppDelegate.h"

@class LVFAppDelegate;

@interface LVFState : NSObject


@property NSMutableDictionary *conditions;
@property NSMutableDictionary *waitTimes;
@property NSMutableDictionary *nots;
@property NSNumber *game;
@property NSNumber *state;
@property LVFAppDelegate *appDel;
@property BOOL special;
@property int counter;
@property NSMutableDictionary* reports;

//initiates
- (id) initWithConditions:(NSMutableDictionary *)conditions andWaitTimes:(NSMutableDictionary *)waits andNots:(NSMutableDictionary *)nots andGame:(NSNumber *)game andState:(NSNumber *)state forDelegate:(LVFAppDelegate *)del isSpecial:(BOOL)isSpec;

//checks if this state is active, returns self if it is, otherwise null
- (LVFState *) checkState;
@end
