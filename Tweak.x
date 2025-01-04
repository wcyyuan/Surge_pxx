#import <CoreFoundation/CoreFoundation.h>
#import <Foundation/Foundation.h>
#include <assert.h>
#import <CommonCrypto/CommonDigest.h>  // 引入CommonCrypto库，提供加密功能
#import <CommonCrypto/CommonCryptor.h>  // 引入CommonCrypto库，提供加密算法
#include <mach-o/dyld.h>  // 引入dyld库，用于动态链接和加载

// 扩展NSMutableURLRequest类，添加curl请求的打印功能
@implementation NSMutableURLRequest(Curl)

- (NSString *)description {  // 重写description方法，用于输出请求的curl命令
    __block NSMutableString *displayString = [NSMutableString stringWithFormat:@"curl -v -X %@", self.HTTPMethod];  // 初始化curl命令，设置请求方法
    
    [displayString appendFormat:@" \'%@\'",  self.URL.absoluteString];  // 添加URL到命令
    
    [self.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {  // 遍历请求头
        [displayString appendFormat:@" -H \'%@: %@\'", key, val];  // 格式化请求头并添加到命令
    }];
    
    if ([self.HTTPMethod isEqualToString:@"POST"] ||
        [self.HTTPMethod isEqualToString:@"PUT"] ||
        [self.HTTPMethod isEqualToString:@"PATCH"]) {  // 如果请求方法是POST、PUT或PATCH
        [displayString appendFormat:@" -d \'%@\'",  // 添加请求体内容
         [[NSString alloc] initWithData:self.HTTPBody encoding:NSUTF8StringEncoding]];  // 将请求体数据转为字符串
    }
    
    return displayString;  // 返回完整的curl命令字符串
}

@end


// 扩展NSString类，提供SHA-256哈希计算功能
@implementation NSString (SHA256)

- (NSData *)SHA256 {  // 添加SHA256计算方法
    const char *s = [self cStringUsingEncoding:NSUTF8StringEncoding];  // 将NSString转换为C字符串
    NSData *keyData = [NSData dataWithBytes:s length:strlen(s)];  // 将C字符串转换为NSData对象

    uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};  // 定义一个缓冲区来存放SHA256的结果
    CC_SHA256(keyData.bytes, (CC_LONG)keyData.length, digest);  // 计算SHA256哈希
    NSData *out = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];  // 将哈希结果转换为NSData
    return out;  // 返回SHA256结果
}

@end


// 定义许可证加密内容
char LicEncContent[] = "\x03\x04\x02NSExtension";  // 这个是许可证加密内容的字节数组

// Hook SGNSARequestHelper类
%hook SGNSARequestHelper 

// Hook方法，拦截request请求，修改请求行为
- (id)request:(NSMutableURLRequest *)req completeBlock:(void (^)(NSData *body, NSURLResponse *resp, NSError *err))completeBlock {
    __auto_type reqRawUrl = [req URL];  // 获取请求的原始URL
    __auto_type reqUrl = [[req URL] absoluteString];  // 获取URL的绝对字符串形式
    if (![reqUrl hasPrefix:@"https://www.surge-activation.com/ios/v3/"]) { return %orig; }  // 如果请求URL不符合特定前缀，调用原始方法
    if (!completeBlock) { return %orig; }  // 如果没有完成回调，调用原始方法
    
    __auto_type wrapper = ^(NSError *error, NSDictionary *data) {  // 创建一个回调包装器
        __auto_type resp = [[NSHTTPURLResponse alloc] initWithURL:reqRawUrl statusCode:200 HTTPVersion:@"1.1" headerFields:@{}];  // 构造一个假的HTTP响应
        NSData *body = [NSJSONSerialization dataWithJSONObject:data options:0 error: &error];  // 将数据转为JSON格式
        completeBlock(body, resp, error);  // 调用完成回调
    };

    NSLog(@"Surge License Request: %@", [req description]);  // 打印请求信息

    if ([reqUrl hasSuffix:@"refresh"]) {  // 如果请求是"refresh"类型，模拟许可证请求
        NSError *err = nil;
        NSDictionary *reqDict = [NSJSONSerialization JSONObjectWithData:req.HTTPBody options:kNilOptions error:&err];  // 解析请求体
        NSString *deviceID = reqDict[@"deviceID"];  // 获取设备ID
        __auto_type keydata = [deviceID SHA256];  // 对设备ID进行SHA256哈希处理
        const char *keybytes = [keydata bytes];  // 获取哈希结果的字节数组
        char licEncOut[32] = { 0 };  // 定义加密输出缓冲区
        size_t encRet = 0;  // 加密结果的大小
        
        NSLog(@"key: %@ %x", keydata, *(uint32_t *)keybytes);  // 打印密钥信息

        // 使用AES加密算法对许可证内容进行加密
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding, 
            keybytes, 0x20, keybytes + 16, 
            LicEncContent, sizeof(LicEncContent),
            licEncOut, 32, 
            &encRet);  // 加密过程
        NSLog(@"encRet: %zu", encRet);  // 打印加密结果的大小

        __auto_type p = [[NSData dataWithBytes:(const void *)licEncOut length:16] base64EncodedStringWithOptions:0];  // 将加密结果转为Base64字符串
        NSLog(@"p: %@", p);  // 打印加密后的Base64字符串
        
        [req setURL:[NSURL URLWithString:@"http://127.0.0.1:65536"]];  // 修改请求的URL为本地地址
        void (^handler)(NSError *error, NSDictionary *data) = ^(NSError *error, NSDictionary *data){  // 定义回调处理
            NSDictionary *licInfo = @{  // 构造许可证信息字典
                    @"deviceID": deviceID,
                    @"expirationDate": @4070880000, // 设置过期时间为2099年
                    @"fusDate": @4070880000,  // 设置fusDate为2099年
                    @"type": @"licensed",  // 设置许可证类型为licensed
                    @"issueDate": [NSNumber numberWithInt:(long)[[NSDate date] timeIntervalSince1970]],  // 设置当前时间为颁发日期
                    @"p": p,  // 添加Base64加密字符串
                };
            NSLog(@"generated licInfo: %@", licInfo);  // 打印生成的许可证信息
            NSData *licInfoData = [NSJSONSerialization dataWithJSONObject:licInfo options:0 error: &error];  // 将许可证信息转为JSON数据
            NSString *licInfoStr = [[NSString alloc] initWithData:licInfoData encoding:NSUTF8StringEncoding];  // 将JSON数据转为字符串
            NSLog(@"generated licInfoJson: %@", licInfoStr);  // 打印许可证信息的JSON字符串

            NSString *licInfoBase64 = [licInfoData base64EncodedStringWithOptions:0];  // 将许可证信息的JSON数据转为Base64字符串
            wrapper(nil, @{  // 通过回调返回许可证信息
                @"license": @{
                    @"policy": licInfoBase64,  // 包含Base64编码的许可证信息
                    @"sign": @""  // 空签名
                }
            });
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil);  // 在主线程上调用回调
        });
    }
    
    if ([reqUrl hasSuffix:@"ac"]) {  // 如果请求是"ac"类型，禁用刷新请求
        [req setURL:[NSURL URLWithString:@"http://127.0.0.1:65536"]];  // 将请求的URL修改为本地地址
        void (^handler)(NSError *error, NSDictionary *data) = ^(NSError *error, NSDictionary *data){
            wrapper(nil, @{});  // 通过回调返回空数据
        };
        dispatch_async(dispatch_get_main_queue(), ^{
            handler(nil, nil);  // 在主线程上调用回调
        });
    }
    
    return %orig;  // 调用原始的方法
}

%end


// Hook SGUProFeatureDefine类，修改解锁时间
%hook SGUProFeatureDefine

- (int64_t) unlockTime {  // 修改解锁时间方法
    return 0;  // 始终返回0，表示永不过期
}

%end


// 绕过OpenSSL的签名验证
void *pEVP_DigestVerifyFinal = NULL;

%hookf(uint64_t, pEVP_DigestVerifyFinal, void *ctx, uint64_t a2, uint64_t a3) {
    %orig;  // 调用原始方法
    NSLog(@"Bypassed surge lic sign check!");  // 打印绕过日志
    return 1;  // 返回1，表示验证成功，绕过签名检查
}

#include <dlfcn.h>

%ctor {
    // 在Surge >= v4.14.0版本中，OpenSSL不再静态链接
    
    NSString *execPath = [[NSBundle mainBundle] executablePath].stringByDeletingLastPathComponent;  // 获取可执行文件的路径
    while ([execPath containsString:@"/PlugIns"]) {
        execPath = execPath.stringByDeletingLastPathComponent;  // 移除插件路径
    }
    NSString *openSSLPath = [NSString stringWithFormat:@"%@/%@", execPath, @"Frameworks/OpenSSL.framework/OpenSSL"];  // 拼接OpenSSL框架路径
    NSLog(@"OpenSSL Framework: %@", openSSLPath);  // 打印OpenSSL路径
    if (![[NSFileManager defaultManager] fileExistsAtPath:openSSLPath]) {  // 如果OpenSSL框架不存在
        // 如果没有OpenSSL框架，使用模式查找
        NSLog(@"Retriving EVP_DigestVerifyFinal using pattern because there's no OpenSSL framework");
        unsigned char needle[] = "\xff\x83\x02\xd1\xf8\x5f\x06\xa9\xf6\x57\x07\xa9\xf4\x4f\x08\xa9\xfd\x7b\x09\xa9\xfd\x43\x02\x91\xf3\x03\x02\xaa\xf4\x03\x01\xaa\xf5\x03\x00\xaa";  // Surge5版本的特征字节
        int needleOffset = 0;  // 偏移量
        
        int imgIndex = -1;  // 图片索引初始化为-1
        const char surgeImagePath[] = "/private/var/containers/Bundle/Application";  // Surge主程序路径
        for (int i = 0; i < _dyld_image_count(); i++) {  // 遍历已加载的动态库
            NSLog(@"Finding Surge module: %s", _dyld_get_image_name(i));  // 打印正在查找的模块名称
            if (!strncmp(_dyld_get_image_name(i), surgeImagePath, sizeof(surgeImagePath)-1)) {
                imgIndex = i;  // 找到Surge模块
                break;
            }
        }
        if (imgIndex == -1) {  // 如果没有找到Surge模块
            NSLog(@"Cannot find surge main executable under %s", surgeImagePath);
            exit(1);  // 退出程序
        }
        NSLog(@"Got Surge module at index %d: %s", imgIndex, _dyld_get_image_name(imgIndex));  // 打印找到的Surge模块信息
        intptr_t imgBase = (intptr_t)_dyld_get_image_vmaddr_slide(imgIndex) + 0x100000000LL;  // 获取模块的基地址
        intptr_t imgBase2 = (intptr_t)_dyld_get_image_header(imgIndex);  // 获取模块头地址
        NSLog(@"Surge image base at %p %p (%s)", (void *)imgBase, (void *)imgBase2, _dyld_get_image_name(imgIndex));  // 打印模块的基地址
        imgBase = imgBase2;  // 使用第二个基地址
        
        // 寻找特定字节序列的位置
        char *pNeedle = (char *)memmem((void *)imgBase, 0x400000, needle, sizeof(needle) - 1);  
        NSLog(@"found pNeedle at %p", pNeedle);  // 打印字节序列的位置
        if(pNeedle == NULL) {  // 如果没有找到字节序列
            exit(1);  // 退出程序
        }
        pEVP_DigestVerifyFinal = pNeedle + needleOffset;  // 将找到的字节地址存入pEVP_DigestVerifyFinal
    } else {  // 如果OpenSSL框架存在
        NSLog(@"OpenSSL framework exists!");  // 打印框架存在的日志
        void *ret = dlopen([openSSLPath UTF8String], RTLD_NOW | RTLD_GLOBAL);  // 动态加载OpenSSL库
        NSLog(@"OpenSSL framework load result: %p", ret);  // 打印加载结果

        MSImageRef image = MSGetImageByName([openSSLPath UTF8String]);  // 获取OpenSSL的动态库
        NSLog(@"Retriving EVP_DigestVerifyFinal using symbol because there's OpenSSL framework: %p", image);  // 打印获取EVP_DigestVerifyFinal符号的过程
        pEVP_DigestVerifyFinal = MSFindSymbol(image, "_EVP_DigestVerifyFinal");  // 查找EVP_DigestVerifyFinal符号
    }
    NSLog(@"Got EVP_DigestVerifyFinal: %p", pEVP_DigestVerifyFinal);  // 打印获取到的EVP_DigestVerifyFinal地址

    %init;  // 完成初始化
}
