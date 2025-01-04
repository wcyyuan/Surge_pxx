# Surge破解 代码解释



## 1. `NSMutableURLRequest` 

```objc
@implementation NSMutableURLRequest(Curl)

- (NSString *)description {
    __block NSMutableString *displayString = [NSMutableString stringWithFormat:@"curl -v -X %@", self.HTTPMethod];
    
    [displayString appendFormat:@" \'%@\'",  self.URL.absoluteString];
    
    [self.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
        [displayString appendFormat:@" -H \'%@: %@\'", key, val];
    }];
    
    if ([self.HTTPMethod isEqualToString:@"POST"] ||
        [self.HTTPMethod isEqualToString:@"PUT"] ||
        [self.HTTPMethod isEqualToString:@"PATCH"]) {
        
        [displayString appendFormat:@" -d \'%@\'",
         [[NSString alloc] initWithData:self.HTTPBody encoding:NSUTF8StringEncoding]];
    }
    
    return displayString;
}

@end

```

## 2.NSString ：SHA-256 哈希计算
```objc
@implementation NSString (SHA256)

- (NSData *)SHA256 {
    const char *s = [self cStringUsingEncoding:NSUTF8StringEncoding];
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];

    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);
    NSData *out = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return out;
}

@end

```
## 3.Hook SGNSARequestHelper
```objc
%hook SGNSARequestHelper 

- (id)request:(NSMutableURLRequest *)req completeBlock:(void (^)(NSData *body, NSURLResponse *resp, NSError *err))completeBlock {
    __auto_type reqRawUrl = [req URL];
    __auto_type reqUrl = [[req URL] absoluteString];
    if (![reqUrl hasPrefix:@"https://www.surge-activation.com/ios/v3/"]) { return %orig; }
    if (!completeBlock) { return %orig; }
    
    __auto_type wrapper = ^(NSError *error, NSDictionary *data) {
        __auto_type resp = [[NSHTTPURLResponse alloc] initWithURL:reqRawUrl statusCode:200 HTTPVersion:@"1.1" headerFields:@{}];
        NSData *body = [NSJSONSerialization dataWithJSONObject:data options:0 error: &error];
        completeBlock(body, resp, error);
    };

    NSLog(@"Surge License Request: %@", [req description]);

    if ([reqUrl hasSuffix:@"refresh"]) { // fake refresh req
        NSError *err = nil;
        NSDictionary *reqDict = [NSJSONSerialization JSONObjectWithData:req.HTTPBody
                                    options:kNilOptions
                                    error:&err];
        NSString *deviceID = reqDict[@"deviceID"];
        __auto_type keydata = [deviceID SHA256];
        const char *keybytes = [keydata bytes];
        char licEncOut[32] = { 0 };
        size_t encRet = 0;
        
        NSLog(@"key: %@ %x", keydata, *(uint32_t *)keybytes);

        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, 
            keybytes, 0x20, keybytes + 16, 
            LicEncContent, sizeof(LicEncContent),
            licEncOut, 32, 
            &encRet);
        NSLog(@"encRet: %zu", encRet);

        __auto_type p = [[NSData dataWithBytes:(const void *)licEncOut length:16] base64EncodedStringWithOptions:0];
        NSLog(@"p: %@", p);
        
        [req setURL:[NSURL URLWithString:@"http://127.0.0.1:65536"]];
        void (^handler)(NSError *error, NSDictionary *data) = ^(NSError *error, NSDictionary *data){
            NSDictionary *licInfo = @{
                    @"deviceID": deviceID,
                    @"expirationDate": @4070880000, // 2099-01-01 00:00:00
                    @"fusDate": @4070880000,
                    @"type": @"licensed",
                    @"issueDate": [NSNumber numberWithInt:(long)[[NSDate date] timeIntervalSince1970]],
                    @"p": p,
                };
            NSLog(@"generated licInfo: %@", licInfo);
            NSData *licInfoData = [NSJSONSerialization dataWithJSONObject:licInfo options:0 error: &error];
            NSString *licInfoStr = [[NSString alloc] initWithData:licInfoData encoding:NSUTF8StringEncoding];
            NSLog(@"generated licInfoJson: %@", licInfoStr);

            NSString *licInfoBase64 = [licInfoData base64EncodedStringWithOptions:0];
            wrapper(nil, @{
                @"license": @{
                    @"policy": licInfoBase64,
                    @"sign": @""
                }
            });
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil);
        });
    }
    
    if ([reqUrl hasSuffix:@"ac"]) { // disable refresh req
        [req setURL:[NSURL URLWithString:@"http://127.0.0.1:65536"]];
        void (^handler)(NSError *error, NSDictionary *data) = ^(NSError *error, NSDictionary *data){
            wrapper(nil, @{});
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil);
        });
    }
    
	return %orig;
}

%end

```
## 4.Hook unlockTime
```objc
%hook SGUProFeatureDefine

- (int64_t) unlockTime {
    return 0;
}

%end

```
## 5.OpenSSL签名验证
```objc
void *pEVP_DigestVerifyFinal = NULL;

%hookf(uint64_t, pEVP_DigestVerifyFinal, void *ctx, uint64_t a2, uint64_t a3) {
    %orig;
    NSLog(@"Bypassed surge lic sign check!");
    return 1;
}

```
## 6.动态加载和查找OpenSSL
```objc
%ctor {
    NSString *execPath = [[NSBundle mainBundle] executablePath].stringByDeletingLastPathComponent;
    while ([execPath containsString:@"/PlugIns"]) {
        execPath = execPath.stringByDeletingLastPathComponent;
    }
    NSString *openSSLPath = [NSString stringWithFormat:@"%@/%@", execPath, @"Frameworks/OpenSSL.framework/OpenSSL"];
    NSLog(@"OpenSSL Framework: %@", openSSLPath);
    if (![[NSFileManager defaultManager] fileExistsAtPath:openSSLPath]) {
        // Static OpenSSL version (<= 4.13.0)
        NSLog(@"Retriving EVP_DigestVerifyFinal using pattern because there's no OpenSSL framework");
        unsigned char needle[] = "\xff\x83\x02\xd1\xf8\x5f\x06\xa9\xf6\x57\x07\xa9\xf4\x4f\x08\xa9\xfd\x7b\x09\xa9\xfd\x43\x02\x91\xf3\x03\x02\xaa\xf4\x03\x01\xaa\xf5\x03\x00\xaa"; // Surge5
        int needleOffset = 0;
        ...
    } else {
        NSLog(@"OpenSSL framework exists!");
        ...
    }
    %init;
}

```
