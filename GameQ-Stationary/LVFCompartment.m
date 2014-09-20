//
//  LVFCompartment.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFCompartment.h"

@implementation LVFCompartment



- (id) initWithName:(NSObject*)name andObject:(NSObject*)obj
{
    self = [super init];
    if (self) {
        _name = name;
        _heldObject = obj;
    }
    return self;
}


@end
