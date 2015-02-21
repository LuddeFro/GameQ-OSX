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
- (id) initWithConditions:(NSMutableDictionary *)conditions andWaitTimes:(NSMutableDictionary *)waits andNots:(NSMutableDictionary *)nots andGame:(NSNumber *)game andState:(NSNumber *)state forDelegate:(LVFAppDelegate *)del isSpecial:(BOOL)isSpec
{
    self = [super init];
    if (self) {
        _conditions = conditions;
        _game = game;
        _state = state;
        _appDel = del;
        _special = isSpec;
        _waitTimes = waits;
        _nots = nots;
        _counter = 0;
        _reports = [[NSMutableDictionary alloc] init];
    }
    return self;
}

//checks if this state is active, returns self if it is, otherwise null
- (LVFState *) checkState
{
    int precount = _counter;
    _counter++;
    [_reports setObject:[NSNumber numberWithBool:true] forKey:[NSNumber numberWithInt:precount]];
    
    
    
    if (_special) {
        if (_appDel.bolSpecialCD) {
            return NULL;
        }
    }
    BOOL haswait = false;
    int longestwait = 0;
    for (NSString* key in _conditions) {
        int wait = ((NSNumber *)[_waitTimes objectForKey:key]).intValue;
        BOOL notting = ((NSNumber *)[_nots objectForKey:key]).boolValue;
        if (wait > 0) {
            NSMutableDictionary* tempDic = [[NSMutableDictionary alloc] init];
            [tempDic setObject:key forKey:@"name"];
            [tempDic setObject:[_waitTimes objectForKey:key] forKey:@"wait"];
            [tempDic setObject:[_nots objectForKey:key] forKey:@"nots"];
            if (haswait == false || wait == longestwait) {
                [tempDic setObject:[NSNumber numberWithBool:true] forKey:@"reports"];
                longestwait = wait;
            } else {
                [tempDic setObject:[NSNumber numberWithBool:false] forKey:@"reports"];
                
            }
            haswait = true;
            [tempDic setObject:[NSNumber numberWithInt:((LVFBuffer *)[_appDel.buffers objectForKey:key]).bufferValue] forKey:@"numpacks"];
            [tempDic setObject:[NSNumber numberWithInt:precount] forKey:@"reportID"];
            [self performSelectorInBackground:@selector(checkUnwrapperForFuture:) withObject:tempDic];
            haswait = true;
        } else {
            
            int a = [[_conditions objectForKey:key] intValue];
            LVFBuffer *buffo = [_appDel.buffers objectForKey:key];
            if (notting) {
                if (buffo.bufferValue >= a) {
                    [_reports setObject:[NSNumber numberWithBool:false] forKey:[NSNumber numberWithInt:precount]];
                    return NULL;
                }
            } else {
                if (buffo.bufferValue < a) {
                    [_reports setObject:[NSNumber numberWithBool:false] forKey:[NSNumber numberWithInt:precount]];
                    return NULL;
                }
            }
        }
        
        
    }
    if (!haswait) {
        return self;
    }
    return NULL;
}

-(void) checkUnwrapperForFuture:(NSMutableDictionary *)tempDic
{
    sleep(((NSNumber *)[tempDic objectForKey:@"wait"]).intValue);
    NSString* name = [tempDic objectForKey:@"name"];
    BOOL bolnots = ((NSNumber *)[tempDic objectForKey:@"nots"]).boolValue;
    int numpacks = ((NSNumber *)[tempDic objectForKey:@"numpacks"]).intValue;
    BOOL reporting = ((NSNumber *)[tempDic objectForKey:@"reports"]).boolValue;
    int repID = ((NSNumber *)[tempDic objectForKey:@"reportID"]).intValue;
    
    [self checkInFuture:name andNumsPacks:numpacks andNotted:bolnots andWillReport:reporting toID:repID];
}

-(void) checkInFuture:(NSString *)key andNumsPacks:(int)numPacks andNotted:(BOOL)notted andWillReport:(BOOL)reporting toID:(int)reportID
{
    int a = numPacks;
    LVFBuffer *buffo = [_appDel.buffers objectForKey:key];
    if (notted) {
        if (buffo.bufferValue >= a) {
            [_reports setObject:[NSNumber numberWithBool:false] forKey:[NSNumber numberWithInt:reportID]];
        }
    } else {
        if (buffo.bufferValue < a) {
            [_reports setObject:[NSNumber numberWithBool:false] forKey:[NSNumber numberWithInt:reportID]];
        }
    }
    if (reporting) {
        if (((NSNumber*)[_reports objectForKey:[NSNumber numberWithInt:reportID]]).boolValue) {
            //no errors found
            [_appDel.wildCards setObject:self forKey:[NSNumber numberWithInt:reportID]];
        } else {
            //a condition didn't match
            [_appDel.wildCards removeObjectForKey:[NSNumber numberWithInt:reportID]];
        }
    }
}

@end
