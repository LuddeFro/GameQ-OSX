//
//  LVFState.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFState.h"

@implementation LVFState


//initiates
- (id) initWithConditions:(NSMutableDictionary *)conditions andGame:(NSNumber *)game andState:(NSNumber *)state forDelegate:(LVFAppDelegate *)del isSpecial:(BOOL)isSpec
{
    self = [super init];
    if (self) {
        _conditions = conditions;
        _game = game;
        _state = state;
        _appDel = del;
        _special = isSpec;
    }
    return self;
}

//checks if this state is active, returns self if it is, otherwise null
- (LVFState *) checkState
{
    if (_special) {
        if (_appDel.bolSpecialCD) {
            return NULL;
        }
    }
    
    for (NSString* key in _conditions) {
        
        LVFBuffer *buffo = [_appDel.buffers objectForKey:key];
        int a = [[_conditions objectForKey:key] intValue];
        
        if (buffo.bufferValue < a) {
            return NULL;
        }
    }
    return self;
}

@end
