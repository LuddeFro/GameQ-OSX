//
//  LVFCapObj.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFCapObj.h"

@implementation LVFCapObj



//increments prebuffers for name if true with comparisons and instance variables
- (void) checkPacketWithSport:(int)sport andDport:(int)dport andWlen:(int)wlen
{
    
    for (NSString* key in _comparisons) {
        
        LVFBuffer *buffo = [_appDel.buffers objectForKey:key];
        int a = [[_comparisons objectForKey:key] intValue];
        
        if (buffo.bufferValue < a) {
            return;
        }
        // do stuff
    }
    
    if (sport <= _maxsport && sport >= _minsport && dport >= _mindport && dport <= _maxdport && wlen <= _maxwlen && wlen >= _minwlen) {
        int previous = 0;
        if (!([_appDel.prebuffers objectForKey:_name] == nil)) {
            previous = [[_appDel.prebuffers objectForKey:_name] intValue];
        }
        previous++;
        [_appDel.prebuffers setObject:[NSNumber numberWithInt:previous] forKey:_name];
        
    }
}

//adds item to comparisons
- (void) addComparisonForName:(NSString *)name andValue:(int)value
{
    [_comparisons setObject:[NSNumber numberWithInt:value] forKey:name];
}

//initiation
- (id) initWithDelegate:(LVFAppDelegate *)del andName:(NSString *)name andMinSport:(int)minsport andMaxSport:(int)maxsport andMinDport:(int)mindport andMaxDport:(int)maxdport andMinWlen:(int)minwlen andMaxWlen:(int)maxwlen andBuffSize:(int)buffSize
{
    self = [super init];
    if (self) {
        _mindport = mindport;
        _minsport = minsport;
        _minwlen = minwlen;
        _maxsport = maxsport;
        _maxdport = maxdport;
        _maxwlen = maxwlen;
        _name = name;
        _comparisons = [[NSMutableDictionary alloc] init];
        _appDel = del;
        
        [del.prebuffers setObject:[NSNumber numberWithInt:0] forKey:name];
        LVFBuffer *buffy = [[LVFBuffer alloc] initWithSize:buffSize];
        [del.buffers setObject:buffy forKey:name];
        
    }
    return self;
    
}

@end