//
//  LVFdataModel.m
//  GameQ-Mobile
//
//  Created by Ludvig Fröberg on 10/23/13.
//  Copyright (c) 2013 Ludvig Fröberg. All rights reserved.
//

#import "LVFDataModel.h"

@implementation LVFDataModel

-(id) initWithAppDelegate:(LVFAppDelegate *)appDel
{
    self = [super init];
    if (self)
    {
        _appDelegate = appDel;
        
        _context = [_appDelegate managedObjectContext];
        NSEntityDescription *entityDescription = [NSEntityDescription entityForName:@"LoginEntity" inManagedObjectContext:_context];
        _request = [[NSFetchRequest alloc] init];
        [_request setEntity:entityDescription];
    }
    return self;
}


- (NSString *) getToken
{
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kToken] encoding:NSUTF8StringEncoding];
    return  string;/*
    return [[NSHost currentHost] localizedName];
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }

    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"token"];
    }
    return nil;*/
}
- (NSString *) getEmail
{
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kEmail] encoding:NSUTF8StringEncoding];
    return  string;/*
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    
    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"email"];
    }
    return nil;*/

}
- (NSNumber *) getBolIsLoggedIn
{
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kBolIsLoggedIn] encoding:NSUTF8StringEncoding];
    if ([string isEqualToString:@"true"]) {
        return [NSNumber numberWithBool:true];
    } else {
        return [NSNumber numberWithBool:false];
    }
    /*
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    
    
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"bolIsLoggedIn"];
    }
    return nil;*/

}
- (NSString *) getDeviceID
{
    
    
    
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kDeviceID] encoding:NSUTF8StringEncoding];
    
    if (string == NULL || [string isEqualToString:@""]) {
        return [[NSHost currentHost] localizedName];
    }
    
    return  string;
    /*
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kAPPID] encoding:NSUTF8StringEncoding];
    return  string;
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == Nil) {
        NSLog(@"Storage files not found");
    }
    for (NSManagedObject *oneObject in objects) {
        return [oneObject valueForKey:@"deviceID"];
    }
    return nil;*/
    
}
- (NSString *) getPass
{
    
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kPass] encoding:NSUTF8StringEncoding];
    return  string;
    
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //return [keyChain getPassword];
}
- (NSString *) getFirstLog
{
    
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kFirstLog] encoding:NSUTF8StringEncoding];
    return  string;
    
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //return [keyChain getPassword];
}
- (NSString *) getUniqueID
{
    
    NSString *string = [[NSString alloc] initWithData:[SSKeychain passwordDataForService:kAPPID account:kUnique] encoding:NSUTF8StringEncoding];
    return  string;
    
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //return [keyChain getPassword];
}
- (void) setUniqueID:(NSString *)string
{
    [SSKeychain setPassword:string forService:kAPPID account:kUnique];
    //[self setSomething:devID forField:@"deviceID"];
}

- (void) setFirstLog:(NSString *)string
{
    [SSKeychain setPassword:string forService:kAPPID account:kFirstLog];
    //[self setSomething:devID forField:@"deviceID"];
}
- (void) setDeviceID:(NSString *)devID
{
    [SSKeychain setPassword:devID forService:kAPPID account:kDeviceID];
    //[self setSomething:devID forField:@"deviceID"];
}
- (void) setPass:(NSString *)pass
{
    [SSKeychain setPassword:pass forService:kAPPID account:kPass];
    //LVFKeyChain *keyChain = [[LVFKeyChain alloc] init];
    //[keyChain setPassword:pass];
    
}
- (void) setToken:(NSString *)token
{
    NSLog(@"setting token: %@", token);
    [SSKeychain deletePasswordForService:kAPPID account:kToken];
    [SSKeychain setPassword:token forService:kAPPID account:kToken];
    NSLog(@"set token");

    //[self setSomething:token forField:@"token"];
}
- (void) setEmail:(NSString *)email
{
    [SSKeychain setPassword:email forService:kAPPID account:kEmail];
    //[self setSomething:email forField:@"email"];
}
- (void) setBolIsLoggedIn:(NSNumber *)isLoggedIn
{
    if (isLoggedIn.boolValue) {
        [SSKeychain setPassword:@"true" forService:kAPPID account:kBolIsLoggedIn];
    } else {
        [SSKeychain setPassword:@"false" forService:kAPPID account:kBolIsLoggedIn];
    }
    //[self setSomething:isLoggedIn forField:@"bolIsLoggedIn"];
}/*
- (void) setSomething:(id)value forField:(NSString *)field
{
    NSLog(@"%@", field);
    NSManagedObject *anObject = nil;
    NSError *error;
    NSArray *objects = [_context executeFetchRequest:_request error:&error];
    if (objects == nil) {
        NSLog(@"objects == nil  ......    (error)");
        //code should be unreachable
    }
    
    if ([objects count] > 0){
        NSLog(@"for loop is called (datamodel updates shit)");
        for (int i = 0; i < objects.count; i++) {
            anObject = [objects objectAtIndex:i];
            [anObject setValue:value forKey:field];
        }
    } else {
        NSLog(@"for loop isn't called(datamodel creates shit that wasnt already there)");
        anObject = [NSEntityDescription insertNewObjectForEntityForName:@"LoginEntity" inManagedObjectContext:_context];
        [anObject setValue:value forKey:field];
    }
    [_context save:&error];
    
}*/
    
    /*
     - (id)initWithIdentifier: (NSString *)identifier accessGroup:(NSString *) accessGroup;
     - (void)setObject:(id)inObject forKey:(id)key;
     - (id)objectForKey:(id)key;*/
@end
