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
    
    
    NSColor *cloudWhite = [NSColor colorWithRed:0.9255 green:0.9411 blue:0.9450 alpha:1];
    
    NSGradient *grad = [[NSGradient alloc] initWithStartingColor:cloudWhite endingColor:cloudWhite];
    //NSGradient *grad = [[NSGradient alloc] initWithStartingColor:myDarkGray endingColor:myDarkGray];
    NSRect windowFrame = [self frame];
    [grad drawInRect:windowFrame angle:90];
    
}

@end
