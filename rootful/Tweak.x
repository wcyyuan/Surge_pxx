//
// Tweak.x
// 有疑问～ 联系 pxx
//

// ---------------------- 导入必要系统库 ----------------------
//
// CoreFoundation：提供底层数据类型、内存管理及基本服务函数。
// Foundation：提供面向对象的基础框架，包括字符串、集合、数据等。
// assert.h：提供断言功能，用于开发时检测逻辑错误。
// CommonCrypto/CommonDigest.h & CommonCryptor.h：提供加密与摘要计算功能，例如 SHA256、AES 。
// mach-o/dyld.h：用于动态链接、加载模块及运行时符号查询。
// UIKit：提供图形界面、事件处理及多媒体支持。
// objc/runtime.h：运行时函数库，允许在运行时操作 Objective-C 对象及类。
// dlfcn.h：提供动态库加载与符号查找接口。
// mach.h：与内核通信、任务管理相关的 API。
// sysctl.h & sys/utsname.h：用于获取系统及硬件信息。
//
#import <CoreFoundation/CoreFoundation.h>           // 核心数据类型与基础服务
#import <Foundation/Foundation.h>                   // 基础框架
#include <assert.h>                                 // 提供断言机制（逻辑检查）
#import <CommonCrypto/CommonDigest.h>               // 加密摘要算法，例如 SHA256
#import <CommonCrypto/CommonCryptor.h>              // 对称加密算法，例如 AES
#include <mach-o/dyld.h>                            // 动态链接库与模块加载
#import <UIKit/UIKit.h>                             // 用户界面框架
#import <objc/runtime.h>                            // Objective-C
#import <dlfcn.h>                                   // 动态库加载与符号解析
#import <mach/mach.h>                               // 内核通信接口
#import <sys/sysctl.h>                              // 系统信息查询接口
#import <sys/utsname.h>                             // 系统及硬件信息查询

// ---------------------- 全局定义 ----------------------
//
// FIXED_EXPIRATION_DATE：定义一个固定的过期时间，通常用于伪造 license 信息。
// LicEncContent：静态许可加密内容的原始字节数据，用于后续生成 license 加密信息。
//
#define FIXED_EXPIRATION_DATE 2524608000
char LicEncContent[] = "\x03\x04\x02NSExtension";

// ---------------------- 函数声明 ----------------------
//
// 声明一系列用于环境检查、加密计算、静态分析混淆等辅助函数。
//
BOOL isDebuggerAttached();
BOOL isRunningInSimulator();
BOOL verifyIntegrity();
NSString* sha256(NSData *data);
void confuseStaticAnalysis();

//
// topViewController：递归查找当前视图控制器树中的顶层控制器。
// 这样做能够确保弹窗等 UI 操作总是在当前活跃界面上展示。
//
static UIViewController* topViewController(UIViewController *rootViewController);

// ---------------------- 分类声明 ----------------------
//
// 扩展 UIViewController，为其增加条件判断与展示弹窗的能力，
// 用于在满足一定条件时主动提醒用户（例如版本问题提示）。
//
@interface UIViewController (AlertExtension)
- (BOOL)shouldShowAlert;
- (void)showAlert;
@end

// ---------------------- 顶层视图控制器相关函数 ----------------------
//
// 此函数通过不断遍历 presentedViewController、UINavigationController 及 UITabBarController
// 的子控制器，递归获取当前最上层的视图控制器，确保 UI 展示时不会出现在已 dismiss 的界面上。
//
static UIViewController* topViewController(UIViewController *rootViewController) {
    while (rootViewController.presentedViewController) {
        rootViewController = rootViewController.presentedViewController;
    }
    if ([rootViewController isKindOfClass:[UINavigationController class]]) {
        return topViewController([(UINavigationController*)rootViewController topViewController]);
    }
    if ([rootViewController isKindOfClass:[UITabBarController class]]) {
        return topViewController([(UITabBarController*)rootViewController selectedViewController]);
    }
    return rootViewController;
}

//
// getActiveTopViewController：获取当前处于前台的 UIWindow，再调用 topViewController 方法
// 获取真正可用于展示 UI 的最上层视图控制器。注意在多场景（UIScene）架构下的处理方式。
//
static UIViewController* getActiveTopViewController() {
    UIWindow *window = nil;
    for (UIWindowScene *scene in [UIApplication sharedApplication].connectedScenes) {
        if (scene.activationState == UISceneActivationStateForegroundActive) {
            window = scene.windows.firstObject;
            break;
        }
    }
    
    if (!window) {
        NSLog(@"没有找到活动窗口");
        return nil;
    }
    
    return topViewController(window.rootViewController);
}

// ---------------------- UIViewController Hook ----------------------
//
// 利用 MobileSubstrate 的 Hook 技术，对 UIViewController 的 viewDidAppear 方法进行拦截，
// 在视图展示后根据条件显示提示弹窗。利用静态变量 alertShown 保证弹窗只显示一次。
//
%hook UIViewController

- (void)viewDidAppear:(BOOL)animated {
    %orig(animated); // 调用原始实现
    // 使用静态变量，确保每个控制器仅触发一次弹窗展示逻辑
    static BOOL alertShown = NO;
    if (!alertShown && [self shouldShowAlert]) {
        alertShown = YES;
        [self showAlert];
    }
}

//
// shouldShowAlert：判断是否满足展示弹窗的条件，
// 例如在调试器或模拟器环境下不展示，以避免开发环境干扰正式提示。
//
%new
- (BOOL)shouldShowAlert {
    // 检测是否存在调试器或在模拟器中运行，若是则不展示弹窗（避免干扰）
    if (isDebuggerAttached() || isRunningInSimulator()) return NO;
    return YES;
}

//
// showAlert：构建并展示一个 UIAlertController 提示弹窗。
// 包括两个操作按钮（“不同意”退出应用，“好的”继续），
// 以达到在条件不满足时主动告知用户当前版本或模块异常的目的。
//
%new
- (void)showAlert {
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"pxx提醒"
                                                                   message:@"surge5.9.0之前版本正常！5.9.0之后版本模块异常！有时间精力～再看看"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    
    UIAlertAction *disagreeAction = [UIAlertAction actionWithTitle:@"不同意"
                                                             style:UIAlertActionStyleCancel
                                                           handler:^(UIAlertAction * _Nonnull action) {
        NSLog(@"点击了退出按钮，应用将退出。");
        exit(0); // 用户点击“不同意”后退出应用
    }];
    
    UIAlertAction *agreeAction = [UIAlertAction actionWithTitle:@"好的"
                                                           style:UIAlertActionStyleDefault
                                                         handler:^(UIAlertAction * _Nonnull action) {
        NSLog(@"点击了好的按钮");
    }];
    
    [alert addAction:disagreeAction];
    [alert addAction:agreeAction];
    
    UIViewController *topVC = getActiveTopViewController();
    if (topVC) {
        NSLog(@"顶层视图控制器：%@", topVC);
        if (topVC.presentedViewController == nil) { // 确保当前没有其他弹窗正在展示
            dispatch_async(dispatch_get_main_queue(), ^{
                if (![topVC isKindOfClass:[UIViewController class]]) {
                    NSLog(@"无法展示弹窗，topVC 无效");
                    return;
                }
                [topVC presentViewController:alert animated:YES completion:nil];
                NSLog(@"弹窗已显示");
            });
        }
    } else {
        NSLog(@"没有能找到顶层视图控制器");
    }
}

%end

// ---------------------- 反调试、反虚拟化与反静态分析 ----------------------
//
// 下面的函数用于检测当前运行环境是否存在调试器，或是否在模拟器中运行，
// 同时包含一些混淆静态分析的伪代码，目的是增加逆向工程的难度。
//

//
// isDebuggerAttached：利用 sysctl 获取进程状态信息，通过判断 P_TRACED 标志位，
// 检测当前进程是否正被调试器附加。
//
BOOL isDebuggerAttached() {
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        // P_TRACED 标志表示当前进程正被调试
        return (info.kp_proc.p_flag & P_TRACED) != 0;
    }
    return NO;
}

//
// isRunningInSimulator：使用 uname 获取系统信息，通过比对 machine 字段判断是否为模拟器，
// x86_64 或 i386 通常标识为模拟器架构（真机多为 arm 架构）。
//
BOOL isRunningInSimulator() {
    struct utsname systemInfo;
    uname(&systemInfo);
    return (strcmp(systemInfo.machine, "x86_64") == 0 || strcmp(systemInfo.machine, "i386") == 0);
}

//
// confuseStaticAnalysis：伪装混淆代码，通过不影响功能的冗余运算和输出，
// 使静态分析工具，比如IDA pro 难以自动化识别代码逻辑，增加逆向难度。
//
void confuseStaticAnalysis() {
    int a = rand() % 100;
    int b = rand() % 100;
    a = a + b;
    b = b * (a - 1);
    if (a > b) printf("目的是混淆静态分析。\n");
    if (a != b) printf("这段代码是伪代码，用来避免静态分析。\n");
}

// ---------------------- 文件完整性校验与 SHA-256 ----------------------
//
// verifyIntegrity：目前仅返回 YES，可在未来实现文件完整性校验机制，
// 用于检测二进制文件或资源文件是否被篡改。
// sha256：计算传入 NSData 的 SHA-256 摘要，并返回十六进制字符串。
//
BOOL verifyIntegrity() {
    return YES;
}

//
// sha256：利用 CommonCrypto 中的 CC_SHA256 计算数据摘要，
// 并将摘要以 hex 格式字符串返回，用于对比或校验数据完整性。
//
NSString* sha256(NSData *data) {
    if (!data) return nil;
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, hash);
    NSMutableString *hashString = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [hashString appendFormat:@"%02x", hash[i]];
    }
    return hashString;
}

// ---------------------- 为 NSData 添加 SHA256 方法 ----------------------
//
// 通过类别扩展为 NSData 添加 SHA256 方法，方便直接调用进行数据摘要计算。
//
@interface NSData (SHA256)
- (NSData *)SHA256;
@end

@implementation NSData (SHA256)
- (NSData *)SHA256 {
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(self.bytes, (CC_LONG)self.length, hash);
    return [NSData dataWithBytes:hash length:CC_SHA256_DIGEST_LENGTH];
}
@end

// ---------------------- 为 NSString 添加 SHA256 方法 ----------------------
//
// 为 NSString 添加 SHA256 方法，先将字符串转为 NSData 后计算 SHA256，
// 返回值为 NSData 类型，便于后续加密运算。
//
@interface NSString (SHA256)
- (NSData *)SHA256;
@end

@implementation NSString (SHA256)
- (NSData *)SHA256 {
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    return [data SHA256];
}
@end

// ---------------------- 扩展 NSMutableURLRequest（打印 curl 命令） ----------------------
//
// 通过重写 description 方法，为 NSMutableURLRequest 添加将请求转换为 curl 命令的能力，
// 方便开发调试时复现请求行为。
//
@implementation NSMutableURLRequest (Curl)
- (NSString *)description {
    __block NSMutableString *displayString = [NSMutableString stringWithFormat:@"curl -v -X %@", self.HTTPMethod];
    [displayString appendFormat:@" '%@'", self.URL.absoluteString];
    [self.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id key, id val, BOOL *stop) {
        [displayString appendFormat:@" -H '%@: %@'", key, val];
    }];
    if ([self.HTTPMethod isEqualToString:@"POST"] ||
        [self.HTTPMethod isEqualToString:@"PUT"] ||
        [self.HTTPMethod isEqualToString:@"PATCH"]) {
        [displayString appendFormat:@" -d '%@'", [[NSString alloc] initWithData:self.HTTPBody encoding:NSUTF8StringEncoding]];
    }
    return displayString;
}
@end

// ---------------------- 拦截所有 403 响应，并返回 200 ----------------------
//
// 对 NSURLSession 的 dataTaskWithRequest:completionHandler: 方法进行 Hook，
// 对 403 响应进行拦截并伪造返回数据，将 HTTP 状态码修改为 200，
// 同时构造伪造的 JSON 数据返回给上层调用者，达到绕过服务器限制的目的。
//
%hook NSURLSession
- (NSURLSessionDataTask *)dataTaskWithRequest:(NSURLRequest *)request
                             completionHandler:(void (^)(NSData *data, NSURLResponse *response, NSError *error))completionHandler {
    NSLog(@"[Surge Hook] Intercepted request: %@", request.URL.absoluteString);
    // 包装 completionHandler，检测响应状态码是否为 403
    void (^wrappedCompletion)(NSData *, NSURLResponse *, NSError *) =
    ^(NSData *data, NSURLResponse *resp, NSError *err) {
        if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
            NSHTTPURLResponse *httpResp = (NSHTTPURLResponse *)resp;
            if ([httpResp statusCode] == 403) {
                NSLog(@"[Surge Hook] Forcing response code 200 for 403 error");
                // 构造伪造的响应数据
                NSDictionary *fakeResponse = @{@"status": @"ok", @"modules": @[]};
                NSData *newBody = [NSJSONSerialization dataWithJSONObject:fakeResponse options:0 error:nil];
                if (!newBody) {
                    NSLog(@"[Surge Hook] Failed to serialize fake response data");
                    completionHandler(nil, resp, [NSError errorWithDomain:@"SurgeHookError" code:500 userInfo:@{NSLocalizedDescriptionKey: @"Failed to serialize fake response"}]);
                    return;
                }
                // 以原响应 header 为基础构造新的 200 响应
                NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:httpResp.URL
                                                                          statusCode:200
                                                                         HTTPVersion:@"1.1"
                                                                        headerFields:httpResp.allHeaderFields];
                completionHandler(newBody, fakeResp, nil);
                return;
            }
        }
        completionHandler(data, resp, err);
    };
    return %orig(request, wrappedCompletion);
}
%end

// ---------------------- SGNSARequestHelper Hook ----------------------
//
// 对 SGNSARequestHelper 的 request:completeBlock: 方法进行 Hook，
// 拦截针对特定 API 路径（例如 /api/modules/v2、/api/license/verify、/api/account/status 等）的请求，
// 直接构造伪造的返回数据而不进行真实网络通信，从而达到绕过后端校验和功能限制的效果。
//
%hook SGNSARequestHelper

- (id)request:(NSMutableURLRequest *)req completeBlock:(void (^)(NSData *body, NSURLResponse *resp, NSError *err))completeBlock {
    __auto_type reqRawUrl = [req URL];
    __auto_type reqUrl = [[req URL] absoluteString];
    
    NSLog(@"[Surge Hook] Intercepted request: %@", reqUrl);
    NSLog(@"[Surge Hook] Headers: %@", req.allHTTPHeaderFields);
    
    if (!completeBlock) {
        return %orig;
    }
    
    // 定义包装器 block，用于生成伪造响应并调用原始 completeBlock
    __auto_type wrapper = ^(NSError *error, NSDictionary *data) {
        __auto_type resp = [[NSHTTPURLResponse alloc] initWithURL:reqRawUrl
                                                       statusCode:200
                                                      HTTPVersion:@"1.1"
                                                     headerFields:@{}];
        NSData *body = [NSJSONSerialization dataWithJSONObject:data options:0 error:nil];
        completeBlock(body, resp, error);
    };
    
    // 针对不同 API 路径分别构造伪造返回数据
    if ([reqUrl containsString:@"/api/modules/v2"]) {
        NSDictionary *fakeModulesResponse = @{
            @"status": @"ok",
            @"code": @(0),
            @"modules": @[
                @{
                    @"id": @"testModule",
                    @"moduleName": @"ExampleModule",
                    @"version": @"1.0.0",
                    @"description": @"A fake module for Surge",
                    @"expireDate": @(FIXED_EXPIRATION_DATE),
                    @"active": @YES,
                    @"licenseType": @"pro",
                    @"plan": @"lifetime",
                    @"status": @"active"
                }
            ]
        };
        NSLog(@"[Surge Hook] Fake `/api/modules/v2` JSON: %@", fakeModulesResponse);
        wrapper(nil, fakeModulesResponse);
        return nil;
    }
    
    if ([reqUrl containsString:@"/api/license/verify"]) {
        NSDictionary *fakeResponse = @{@"status": @"ok", @"modules": @[]};
        NSLog(@"[Surge Hook] Fake `/api/license/verify` response: %@", fakeResponse);
        wrapper(nil, fakeResponse);
        return nil;
    }
    
    if ([reqUrl containsString:@"/api/account/status"] ||
        [reqUrl containsString:@"/api/config/sync"] ||
        [reqUrl containsString:@"/api/user/profile"]) {
        NSDictionary *fakeResponse = @{@"status": @"ok"};
        NSLog(@"[Surge Hook] Fake simple JSON for %@", reqUrl);
        wrapper(nil, fakeResponse);
        return nil;
    }
    
    // 针对带 refresh 后缀的请求，进行特殊处理
    if ([reqUrl hasSuffix:@"refresh"]) {
        NSError *err = nil;
        NSDictionary *reqDict = [NSJSONSerialization JSONObjectWithData:req.HTTPBody
                                                                options:kNilOptions
                                                                  error:&err];
        NSString *deviceID = reqDict[@"deviceID"];
        NSLog(@"[Surge Hook] Current deviceID (refresh): %@", deviceID);
        
        // 使用 NSString 分类方法 SHA256（返回 NSData*）生成 keydata
        NSData *keydata = [[deviceID dataUsingEncoding:NSUTF8StringEncoding] SHA256];
        const char *keybytes = [keydata bytes];
        char licEncOut[32] = { 0 };
        size_t encRet = 0;
        
        // 使用 AES 对 LicEncContent 进行加密，注意此处密钥和 IV 均取自 keydata 的不同部分
        CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
                keybytes, 0x20, keybytes + 16,
                LicEncContent, sizeof(LicEncContent),
                licEncOut, 32, &encRet);
        
        // 取加密结果前 16 字节进行 Base64 编码
        __auto_type p = [[NSData dataWithBytes:licEncOut length:16]
                          base64EncodedStringWithOptions:0];
        
        // 强制修改请求 URL 指向本地无效地址（通常用于阻断真实网络请求）
        [req setURL:[NSURL URLWithString:@"http://127.0.0.1:65536"]];
        
        NSInteger expirationDate = FIXED_EXPIRATION_DATE;
        NSDictionary *fakeLicenseJSON = @{
            @"license": @{
                @"policy": [[NSJSONSerialization dataWithJSONObject:@{
                    @"deviceID": deviceID,
                    @"expirationDate": @(expirationDate),
                    @"fusDate": @(expirationDate),
                    @"type": @"licensed",
                    @"issueDate": @((NSInteger)[[NSDate date] timeIntervalSince1970]),
                    @"p": p
                } options:0 error:nil] base64EncodedStringWithOptions:0],
                @"sign": @""  // 空签名，绕过签名验证
            }
        };
        NSLog(@"[Surge Hook] Fake `refresh` license JSON: %@", fakeLicenseJSON);
        
        wrapper(nil, fakeLicenseJSON);
        return nil;
    }
    
    return %orig;
}

%end

// ---------------------- SGAPIManager Hook ----------------------
//
// 对 SGAPIManager 的 performRequest:completion: 方法进行 Hook，
// 针对 /api/modules/v2 请求直接返回伪造的模块数据，
// 实现绕过服务器模块校验的目的。
//
%hook SGAPIManager

- (void)performRequest:(NSURLRequest *)request completion:(void (^)(NSData *, NSURLResponse *, NSError *))completion {
    if ([request.URL.path containsString:@"/api/modules/v2"]) {
        NSDictionary *fakeModulesResponse = @{
            @"status": @"ok",
            @"code": @(0),
            @"modules": @[
                @{
                    @"id": @"testModule",
                    @"moduleName": @"ExampleModule",
                    @"version": @"1.0.0",
                    @"description": @"A fake module for Surge",
                    @"expireDate": @(FIXED_EXPIRATION_DATE),
                    @"active": @YES,
                    @"licenseType": @"pro",
                    @"plan": @"lifetime",
                    @"status": @"active"
                }
            ]
        };
        NSLog(@"[Surge Hook] Fake /api/modules/v2 response: %@", fakeModulesResponse);
        NSData *body = [NSJSONSerialization dataWithJSONObject:fakeModulesResponse options:0 error:nil];
        NSHTTPURLResponse *fakeResp = [[NSHTTPURLResponse alloc] initWithURL:request.URL
                                                                  statusCode:200
                                                                 HTTPVersion:@"1.1"
                                                                headerFields:@{}];
        completion(body, fakeResp, nil);
        return;
    }
    %orig;
}

%end

// ---------------------- NSURLSessionDataTask Hook ----------------------
//
// Hook NSURLSessionDataTask 的 resume 方法，对特定请求记录日志，
// 并在某些请求路径下强制输出伪造响应提示信息，
// 同时仍调用原始 resume 方法以保证任务继续执行。
//
%hook NSURLSessionDataTask

- (void)resume {
    NSLog(@"[Surge Hook] NSURLSessionDataTask resume: %@", self.originalRequest.URL.absoluteString);
    NSString *reqUrl = self.originalRequest.URL.absoluteString;
    if ([reqUrl containsString:@"/api/modules/"]) {
        NSLog(@"[Surge Hook] Force-fake /api/modules/ response -> 200");
    }
    %orig;
}

%end

// ---------------------- SGULicenseViewController Hook ----------------------
//
// 对 SGULicenseViewController 中处理 license 响应的函数进行 Hook，
// 修改内部数据结构，对 license 信息进行伪造修改，如修改 expirationDate、plan 等字段，
// 同时增加设备信息，确保最终 license 数据符合预期，达到绕过校验的效果。
//
@interface SGULicenseViewController : UIViewController
@property (nonatomic, strong) NSDictionary *response;
@end

%hook SGULicenseViewController

// 强制在类加载时 Hook
+ (void)load {
    NSLog(@"[Surge Hook] SGULicenseViewController 被 Hook");
}

// Hook handleResponse 方法，确保 response 数据被正确处理
- (void)handleResponse:(NSDictionary *)response {
    NSLog(@"[Surge Hook] handleResponse 被调用: %@", response);
    %orig(response);
}

// Hook handleAsyncResponse，确保异步请求的 response 数据被正确处理
- (void)handleAsyncResponse:(NSDictionary *)response {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSLog(@"[Surge Hook] handleAsyncResponse 被调用: %@", response);
        %orig(response);
    });
}

// Hook reloadCells，伪造 License 数据并刷新 UI
- (void)reloadCells {
    // 获取私有成员 _response
    NSDictionary *response = object_getIvar(self, class_getInstanceVariable([self class], "_response"));
    if (!response) {
        NSLog(@"[Surge Hook] _response 为空，调用原始方法");
        %orig;
        return;
    }

    // 伪造 License 数据
    NSMutableDictionary *mutableResponse = [response mutableCopy];
    NSMutableDictionary *license = [mutableResponse[@"license"] mutableCopy] ?: [NSMutableDictionary dictionary];

    NSInteger expirationDate = FIXED_EXPIRATION_DATE;
    license[@"email"] = @"pxx@gmail.com";
    license[@"fusDate"] = @(expirationDate);
    license[@"orderID"] = @"pxx917144686";
    license[@"expirationDate"] = @(expirationDate);
    license[@"plan"] = @"lifetime";
    license[@"status"] = @"active";
    license[@"licenseType"] = @"pro";
    mutableResponse[@"license"] = license;

    // 添加当前设备信息
    NSString *deviceName = [[UIDevice currentDevice] name];
    NSMutableArray *devices = [NSMutableArray array];
    [devices addObject:@{
        @"id": @"1",
        @"model": @"当前设备",
        @"name": deviceName ?: @"当前设备"
    }];
    mutableResponse[@"devices"] = devices;
    mutableResponse[@"inactive"] = @(0);

    // 更新私有变量 _response
    object_setIvar(self, class_getInstanceVariable([self class], "_response"), [mutableResponse copy]);

    NSLog(@"[Surge Hook] _response 变量已修改: %@", mutableResponse);
    
    // 触发 UI 刷新
    dispatch_async(dispatch_get_main_queue(), ^{
        [self.view setNeedsDisplay];
    });

    %orig;
}

%end

// ---------------------- SGUProFeatureDefine Hook ----------------------
//
// 通过 Hook SGUProFeatureDefine 的 unlockTime 方法，将解锁时间强制返回 0，
// 达到让应用认为所有专业功能已解锁的目的。
//
%hook SGUProFeatureDefine

- (int64_t)unlockTime {
    return 0;
}

%end


// ---------------------- 绕过 OpenSSL 签名验证 ----------------------
//
// 以下代码通过 Hook pEVP_DigestVerifyFinal，实现绕过 OpenSSL 签名验证，
// 从而使得 license 签名校验始终返回通过状态。
//
void *pEVP_DigestVerifyFinal = NULL;

%hookf(uint64_t, pEVP_DigestVerifyFinal, void *ctx, uint64_t a2, uint64_t a3) {
    %orig;
    NSLog(@"Bypassed surge lic sign check!");
    return 1; // 强制返回 1 表示验证成功
}

#include <dlfcn.h>

//
// %ctor 构造函数，在动态库加载时执行，负责初始化 pEVP_DigestVerifyFinal 函数指针。
// 根据 OpenSSL 框架是否存在分别采用不同的获取方式：
// 1. 如果 OpenSSL 框架不存在，则通过内存扫描（memmem）在 Surge 主程序中寻找指定字节模式；
// 2. 如果存在，则通过 dlopen 及 MSFindSymbol 获取符号地址。
//
%ctor {
    // 获取应用可执行文件目录，排除 PlugIns 目录（适用于 App Bundle 结构）
    NSString *execPath = [[NSBundle mainBundle] executablePath].stringByDeletingLastPathComponent;
    while ([execPath containsString:@"/PlugIns"]) {
        execPath = execPath.stringByDeletingLastPathComponent;
    }
    // 构造 OpenSSL 框架路径
    NSString *openSSLPath = [NSString stringWithFormat:@"%@/%@", execPath, @"Frameworks/OpenSSL.framework/OpenSSL"];
    NSLog(@"OpenSSL Framework: %@", openSSLPath);
    if (![[NSFileManager defaultManager] fileExistsAtPath:openSSLPath]) {
        NSLog(@"Retriving EVP_DigestVerifyFinal using pattern because there's no OpenSSL framework");
        // 定义目标字节模式，用于内存搜索。此模式为经过精心挑选的字节序列，便于识别签名验证函数的位置。
        unsigned char needle[] = "\xff\x83\x02\xd1\xf8\x5f\x06\xa9\xf6\x57\x07\xa9\xf4\x4f\x08\xa9\xfd\x7b\x09\xa9\xfd\x43\x02\x91\xf3\x03\x02\xaa\xf4\x03\x01\xaa\xf5\x03\x00\xaa";
        int needleOffset = 0;
        int imgIndex = -1;
        // 搜索路径中常见的 Surge 应用模块目录
        const char surgeImagePath[] = "/private/var/containers/Bundle/Application";
        // 遍历所有已加载模块，查找主模块
        for (int i = 0; i < _dyld_image_count(); i++) {
            NSLog(@"Finding Surge module: %s", _dyld_get_image_name(i));
            if (!strncmp(_dyld_get_image_name(i), surgeImagePath, sizeof(surgeImagePath)-1)) {
                imgIndex = i;
                break;
            }
        }
        if (imgIndex == -1) {
            NSLog(@"Cannot find surge main executable under %s", surgeImagePath);
            exit(1);
        }
        NSLog(@"Got Surge module at index %d: %s", imgIndex, _dyld_get_image_name(imgIndex));
        // 获取模块的内存基址（注意使用 _dyld_get_image_header 返回的是 Mach-O header 地址）
        intptr_t imgBase = (intptr_t)_dyld_get_image_vmaddr_slide(imgIndex) + 0x100000000LL;
        intptr_t imgBase2 = (intptr_t)_dyld_get_image_header(imgIndex);
        NSLog(@"Surge image base at %p %p (%s)", (void *)imgBase, (void *)imgBase2, _dyld_get_image_name(imgIndex));
        imgBase = imgBase2; // 使用 header 地址进行内存搜索
        // 在指定内存区域内搜索目标字节模式
        char *pNeedle = (char *)memmem((void *)imgBase, 0x400000, needle, sizeof(needle)-1);
        NSLog(@"found pNeedle at %p", pNeedle);
        if (pNeedle == NULL) {
            exit(1);
        }
        pEVP_DigestVerifyFinal = pNeedle + needleOffset;
    } else {
        NSLog(@"OpenSSL framework exists!");
        // 加载 OpenSSL 框架动态库
        void *ret = dlopen([openSSLPath UTF8String], RTLD_NOW | RTLD_GLOBAL);
        NSLog(@"OpenSSL framework load result: %p", ret);
        // 利用 MSGetImageByName 与 MSFindSymbol 获取 EVP_DigestVerifyFinal 符号地址
        MSImageRef image = MSGetImageByName([openSSLPath UTF8String]);
        NSLog(@"Retriving EVP_DigestVerifyFinal using symbol because there's OpenSSL framework: %p", image);
        pEVP_DigestVerifyFinal = MSFindSymbol(image, "_EVP_DigestVerifyFinal");
    }
    NSLog(@"Got EVP_DigestVerifyFinal: %p", pEVP_DigestVerifyFinal);
    %init;
}
