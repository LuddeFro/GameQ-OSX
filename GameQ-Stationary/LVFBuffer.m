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
@property int size;

@end

@implementation LVFBuffer

@synthesize array;
@synthesize intInc;


- (id) initWithSize:(int)size
{
    _size = size;
    self = [super init];
    if (self)
    {
        array = [[NSMutableArray alloc] init];
        for (int j = 0; j<_size; j++) {
            [array insertObject:[NSNumber numberWithInt:0] atIndex:j];
        }
        intInc = 0;
    }
    return self;
    
}


- (int) bufferValue
{
    int value = 0;
    for (int j = 0; j<_size; j++) {
        value += [[array objectAtIndex:j] integerValue];
    }
    return value;
}

- (void) increment:(int)value
{
    //NSLog(@"Incrementing %d", intInc);
    //NSLog(@"%@, %@, %@, %@, %@", [array objectAtIndex:0], [array objectAtIndex:1], [array objectAtIndex:2], [array objectAtIndex:3], [array objectAtIndex:4]);
    [array replaceObjectAtIndex:intInc withObject:[NSNumber numberWithInt:value]];
    
    if (intInc >= (_size-1)) {
        intInc = 0;
    } else {
        intInc++;
    }
    
}

- (void) clear
{
    for (int j = 0; j<_size; j++) {
        [array replaceObjectAtIndex:j withObject:[NSNumber numberWithInt:0]];
    }
}





@end
