//
//  LVFCompartment.h
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/09/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LVFCompartment : NSObject


@property NSObject* name;
@property NSObject *heldObject;

- (id) initWithName:(NSObject*)name andObject:(NSObject*)obj;

@end
