//
//  CheckTest.m
//  CheckDemo
//
//  Created by ijiami on 2022/2/18.
//

#import "CheckTestOC.h"
#import <fmdb/FMDB.h>
#import <Network/Network.h>
#import <sys/stat.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>
//sysctl反调试
#include <stdio.h>
#include <sys/types.h>
//#include <unistd.h>
#include <sys/sysctl.h>
#include <stdlib.h>

@implementation CheckTestOC

+ (void)testAll
{
    // 数据库明文存储风险
    [self testdatabase];
    
    // 越狱设备运行风险
    NSLog(@">>>>>checkIsJailbroken = %d", isJailbroken());
    
    // 动态调试攻击风险
    bool reult = disable_debug_sysctl();
    NSLog(@"检测是否有调试应用 = %d", reult);
    
    // 检测是否使用代理
    NSLog(@">>>>>iproxy:%d", [[self class] isSettingProxy]);
    
    // 注入攻击风险
    if (IJMCheckInsertWhiteList() || IJMCheckInsertLib()) {
        NSLog(@"检测到动态库注入");
    }
    else
    {
        NSLog(@"没有检测到动态库注入");
    }
    
    // 篡改和二次打包风险
#warning 此处函数参数为打包证书的teamID, 可先用发布证书打包出来后，然后查看打印日志得到，也可使用ldid -e <macho文件>得到
    BOOL isOrigin = [self checkCodeSignWithProvisionID:@"K294UE6ZZL"];
    NSLog(@"是否未篡改, isOrigin = %d", isOrigin);
}

#pragma mark - 数据库明文存储风险
/// 数据库明文存储风险
/// 通过FMDB+SQLCipher解决
+ (void)testdatabase
{
    NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
    NSString *documentDir = [paths objectAtIndex:0];
    NSString *filepath = [NSString stringWithFormat:@"%@/test.db", documentDir];
    FMDatabase *datebase = [[FMDatabase alloc] initWithPath:filepath];
    [datebase open];
//#warning 设置密码，自己修改
    [datebase setKey:@"123456"];
}

#pragma mark - 越狱设备运行风险
/// 越狱设备运行风险
__attribute__((always_inline))
static bool isJailbroken()
{
    bool jailbroken = false;
    NSString *cydiaPath = @"/Applications/Cydia.app";
    NSString *Mobile = @"/Library/MobileSubstrate/MobileSubstrate.dylib";
    
    if([[NSFileManager defaultManager] fileExistsAtPath:cydiaPath]) {
        jailbroken = true;
    }

    if ([[NSFileManager defaultManager] fileExistsAtPath:Mobile]){
        jailbroken = true;
    }

    // 使用stat系列函数检测Cydia等工具
    struct stat stat_info1;
    if (0 == stat("/Applications/Cydia.app", &stat_info1)) {
        jailbroken = true;
    }
    
    struct stat stat_info2;
    if (0 == lstat("/Applications/Cydia.app", &stat_info2)) {
        jailbroken = true;
    }
    
    char *env = getenv("DYLD_INSERT_LIBRARIES");
    if(env){
        jailbroken = true;
    }

    return jailbroken;
}

#pragma mark - 动态调试攻击风险
/// 动态调试攻击风险
__attribute__((always_inline))
static bool disable_debug_sysctl(void) {
    /**
     返回ture如果当前进程被调试（包括在调试器下运行以及有调试器附加）
     */
    int mib[4];
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    
    //初始化flag，如果sysctl因一些奇怪的原因查询失败，用这个预设值
    info.kp_proc.p_flag = 0;
    
    //初始化mib数组，用来告诉sysctl我们需要查询的进程信息
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    
    if (sysctl(mib, sizeof(mib) / sizeof(*mib), &info, &info_size, NULL, 0) == -1) {
        perror("perror sysctl");
        exit(-1);
    }
    return ((info.kp_proc.p_flag & P_TRACED) != 0);
}

#pragma mark - 检测是否使用代理
/// 检测应用是否使用代理
+ (BOOL)isSettingProxy
{
    CFDictionaryRef dicRef = CFNetworkCopySystemProxySettings();
    const CFStringRef proxyCFstr = CFDictionaryGetValue(dicRef, (const void*)kCFNetworkProxiesHTTPProxy);
    NSString *proxy = (__bridge NSString*)(proxyCFstr);
    if(proxy)
    {
        return YES;
    }
    else
    {
        return NO;
    }
}

#pragma mark - 注入攻击风险防护
/// 注入攻击风险防护
typedef char* _Nullable (*GET_ENV_TYPE)(const char *);
static inline bool __attribute__((optnone))IJMCheckInsertLib()
{
    GET_ENV_TYPE get_env = getenv;
    char *env = get_env("DYLD_INSERT_LIBRARIES");
    return env!=NULL;//不为NULL表示有动态库注入
}

static NSMutableArray *_whitelistFramework;
static inline bool __attribute__((optnone))IJMCheckInsertWhiteList()
{
    _whitelistFramework = [NSMutableArray array];
    // 添加动态库
#warning 动态库列表，如果不知道，可以调试看下面代码打印的数据, 然后在这里修改
    [_whitelistFramework addObject:@"/TestFramework.framework/TestFramework"];
    
    int count = _dyld_image_count();
    for (int i = 0; i < count; i++) {
        //遍历拿到库名称
        const char * imageName = _dyld_get_image_name(i);
        NSString *filePath = [[NSString alloc]initWithBytes:imageName length:strlen(imageName) encoding:NSUTF8StringEncoding];
        NSArray *arrs = [filePath componentsSeparatedByString:@".app/Frameworks"];
//        NSLog(@"filePath = %@", filePath);
        if (arrs.count > 1) {
            NSLog(@"arrs[1] = %@", arrs[1]);
            if (![_whitelistFramework containsObject:arrs[1]]) {
                return YES;
            }
        }
    }
    return NO;
}

#pragma mark - 篡改和二次打包风险
/// 篡改和二次打包风险
/// 参数为打包证书的teamID, 可先用发布证书打包出来后，然后查看打印日志得到，也可使用ldid -e <macho文件>得到
+ (BOOL)checkCodeSignWithProvisionID:(NSString *)provisionID
{
    // 描述文件路径
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:embeddedPath]) {
        // 读取application-identifier
        NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:NSASCIIStringEncoding error:nil];
        NSArray *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        for (int i = 0; i < embeddedProvisioningLines.count; i++) {
            if ([[embeddedProvisioningLines objectAtIndex:i] rangeOfString:@"application-identifier"].location != NSNotFound &&
                ((i+1) < embeddedProvisioningLines.count))
            {
                NSRange rangePrefix = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"<string>"];
                NSRange rangeSuffix = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"</string>"];
                if (rangePrefix.location != NSNotFound && rangeSuffix.location != NSNotFound) {
                    NSRange range = NSMakeRange(rangePrefix.location+rangePrefix.length, rangeSuffix.location - (rangePrefix.location+rangePrefix.length));
                    NSString *fullIdentifier = [[embeddedProvisioningLines objectAtIndex:i+1] substringWithRange:range];
                    NSLog(@"%@", fullIdentifier);
                    NSArray *identifierComponents = [fullIdentifier componentsSeparatedByString:@"."];
                    NSString *appIdentifier = [identifierComponents firstObject];
                    // 对比签名ID
                    if (![appIdentifier isEqual:provisionID])
                    {
                        return NO;
                    }
                    else
                    {
                        return YES;
                    }
                }
            }
        }
    }
    return YES;
}

@end
