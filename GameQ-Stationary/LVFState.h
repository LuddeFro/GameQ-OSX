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
@property NSNumber *game;
@property NSNumber *state;
@property LVFAppDelegate *appDel;
@property BOOL special;

//initiates
- (id) initWithConditions:(NSMutableDictionary *)conditions andGame:(NSNumber *)game andState:(NSNumber *)state forDelegate:(LVFAppDelegate *)del isSpecial:(BOOL)isSpec;

//checks if this state is active, returns self if it is, otherwise null
- (LVFState *) checkState;

@end
