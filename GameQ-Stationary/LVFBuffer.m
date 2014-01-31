//
//  LVFBuffer.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 17/01/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFBuffer.h"

@interface LVFBuffer ()

@property NSMutableArray *array;
@property int intInc;

@end

@implementation LVFBuffer

@synthesize array;
@synthesize intInc;


- (id) init
{
    self = [super init];
    if (self)
    {
        array = [[NSMutableArray alloc] init];
        for (int j = 0; j<5; j++) {
            [array insertObject:[NSNumber numberWithInt:0] atIndex:j];
        }
        intInc = 0;
    }
    return self;
    
}


- (int) bufferValue
{
    int value = 0;
    for (int j = 0; j<5; j++) {
        value += [[array objectAtIndex:j] integerValue];
    }
    return value;
}

- (void) increment:(int)value
{
    [array insertObject:[NSNumber numberWithInt:value] atIndex:intInc];
    
    if (intInc >=4) {
        intInc = 0;
    } else {
        intInc++;
    }
    
}





@end
