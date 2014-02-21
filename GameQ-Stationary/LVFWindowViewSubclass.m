//
//  LVFWindowViewSubclass.m
//  GameQ-Stationary
//
//  Created by Ludvig Fröberg on 20/02/14.
//  Copyright (c) 2014 Ludvig Fröberg. All rights reserved.
//

#import "LVFWindowViewSubclass.h"

@implementation LVFWindowViewSubclass

- (id)initWithFrame:(NSRect)frame
{
    self = [super initWithFrame:frame];
    if (self) {
        // Initialization code here.
    }
    return self;
}
/*
- (void)drawRect:(NSRect)dirtyRect
{
	[super drawRect:dirtyRect];
	
    // Drawing code here.
}*/

- (void)drawRect:(NSRect)dirtyRect
{
    NSColor *blueness = [NSColor colorWithCalibratedRed:0.43 green:0.853 blue:0.947 alpha:1];
    
    NSColor *whiteness = [NSColor colorWithCalibratedRed:1 green:1 blue:1 alpha:1];
    
    NSGradient *grad = [[NSGradient alloc] initWithStartingColor:whiteness endingColor:blueness];
    NSRect windowFrame = [self frame];
    [grad drawInRect:windowFrame angle:90];
    
}

@end
