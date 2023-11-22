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
    
#pragma mark 越狱设备运行风险
    // 越狱设备运行风险
    if (isJailbroken()) {
        NSLog(@">>>>>检测到越狱设备运行风险");
        exit(0);
    }
    
#pragma mark 动态调试攻击风险
    // 动态调试攻击风险
    if (disable_debug_sysctl()) {
        NSLog(@"检测到有调试应用");
#ifndef DEBUG
        exit(0);
#endif
    }
    
#pragma mark 检测是否使用代理
    // 检测是否使用代理
    if (isSettingProxy()) {
        NSLog(@"检测到有使用网络代理, 可能存在抓包风险");
        exit(0);
    }
    
#pragma mark 注入攻击风险
    // 注入攻击风险
    if (IJMCheckInsertWhiteList() || IJMCheckInsertLib())
    {
        NSLog(@"检测到动态库注入");
        exit(0);
    }
    
#pragma mark 篡改和二次打包风险
    // 篡改和二次打包风险
#warning 此处函数参数为打包证书的teamID, 可先用发布证书打包出来后，然后查看打印日志得到，也可使用ldid -e <macho文件>得到
    if (!checkCodeSignIsNotChange(@"K294UE6ZZL"))
    {
        NSLog(@"检测到应用被重签名");
        exit(0);
    }
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
__attribute__((always_inline)) static bool isJailbroken()
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
__attribute__((always_inline)) static bool disable_debug_sysctl(void) {
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
__attribute__((always_inline)) static bool isSettingProxy(void)
{
    // 获取系统代理设置的 CFDictionaryRef
    CFDictionaryRef dicRef = CFNetworkCopySystemProxySettings();
    // 获取 HTTP 代理设置的 CFStringRef
    const CFStringRef proxyCFstr = CFDictionaryGetValue(dicRef, (const void *)kCFNetworkProxiesHTTPProxy);
    // 将 CFStringRef 转换为 NSString
    NSString *proxy = (__bridge NSString *)(proxyCFstr);
    // 如果代理不为空，则返回 true，表示系统设置了代理；否则返回 false，表示系统没有设置代理
    return ((proxy != NULL) ? true : false);
}


#pragma mark - 注入攻击风险防护
/*
 这段代码使用了 getenv 函数来获取名为 DYLD_INSERT_LIBRARIES 的环境变量的值，并将其赋给变量 env。如果该环境变量存在且其值不为 NULL，则函数将返回 true，表示有动态库被注入到当前进程中；否则返回 false，表示没有动态库被注入。

 这种检查通常用于检测动态库是否被恶意注入到进程中，因为某些恶意行为可能会利用 DYLD_INSERT_LIBRARIES 环境变量来加载恶意动态库以实施攻击或监视进程行为。
 */
typedef char* _Nullable (*GET_ENV_TYPE)(const char *);
__attribute__((always_inline)) static bool IJMCheckInsertLib()
{
    // 定义一个函数指针变量，用于获取环境变量值
    GET_ENV_TYPE get_env = getenv;
    // 获取环境变量 "DYLD_INSERT_LIBRARIES" 的值
    char *env = get_env("DYLD_INSERT_LIBRARIES");
    // 返回判断结果，如果环境变量的值不为 NULL，则表示有动态库被注入
    return env != NULL;
}

/*
 这段代码首先初始化了一个 _whitelistFramework 的可变数组作为动态库的白名单，并向其中添加了一个动态库路径字符串。然后，它使用 _dyld_image_count() 函数获取当前进程加载的动态库数量，并通过 _dyld_get_image_name() 获取每个加载的动态库名称。

 接下来，它将获取的动态库名称转换为 NSString，并通过 componentsSeparatedByString: 方法根据 ".app/Frameworks" 进行分割。如果分割后的结果大于1（即存在分割后的内容），它将检查分割后的内容是否在白名单中，如果不在，则返回 YES，表示有动态库未在白名单内。如果所有动态库都在白名单中，则最终返回 NO，表示所有动态库都在白名单内。
 
 这种检查通常用于检测是否有非预期的动态库被加载，以便于进行安全性检查和防范未授权的动态库加载。
 */
static NSMutableArray *_whitelistFramework;
__attribute__((always_inline)) static bool IJMCheckInsertWhiteList() {
    // 初始化一个白名单数组
    _whitelistFramework = [NSMutableArray array];
    // 添加一个动态库到白名单中
#warning 在这里修改动态库列表，如果不清楚列表内容，可以通过看下面的代码打印数据后再进行修改, 
    // 比如这个demo里面动态库只有TestFramework.framework, 则进行下面添加即可
    [_whitelistFramework addObject:@"/TestFramework.framework/TestFramework"];
    
    // 获取当前进程加载的动态库数量
    int count = _dyld_image_count();
    // 遍历加载的动态库
    for (int i = 0; i < count; i++) {
        // 获取动态库名称
        const char *imageName = _dyld_get_image_name(i);
        // 将 C 字符串转换为 NSString
        NSString *filePath = [[NSString alloc] initWithBytes:imageName length:strlen(imageName) encoding:NSUTF8StringEncoding];
        // 根据 ".app/Frameworks" 进行字符串分割
        NSArray *arrs = [filePath componentsSeparatedByString:@".app/Frameworks"];
        // 检查是否有分割后的内容
        if (arrs.count > 1) {
            NSLog(@"当前库名字 = %@", arrs[1]);
            // 检查白名单中是否包含分割后的内容
            if (![_whitelistFramework containsObject:arrs[1]]) {
                return YES; // 如果不在白名单中，则返回 YES，表示有动态库未在白名单内
            }
        }
    }
    return NO; // 如果所有动态库均在白名单中，则返回 NO，表示所有动态库都在白名单内
}

#pragma mark - 篡改和二次打包风险
/*
 这段代码通过检查应用的嵌入式描述文件（mobileprovision）中的 application-identifier 来获取应用的标识符，并与给定的团队标识（Team ID）进行比较。
 如果描述文件存在且标识符匹配给定的 Team ID，则返回 true，否则返回 false。
 如果描述文件不存在或者无法找到相关信息，默认情况下返回 true。
 这种检查可用于验证应用是否被篡改或未经授权地重新签名。
 */
/// 篡改和二次打包风险
/// 参数为打包证书的teamID, 可先用发布证书打包出来后，然后查看打印日志得到，也可使用ldid -e <macho文件>得到
__attribute__((always_inline)) static bool checkCodeSignIsNotChange(NSString *teamID)
{
    // 获取嵌入式描述文件路径，它存储在编译后的 IPA 包中，解压 IPA 包可以找到这个证书文件
    NSString *embeddedPath = [[NSBundle mainBundle] pathForResource:@"embedded" ofType:@"mobileprovision"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:embeddedPath]) {
        // 读取描述文件内容
        NSString *embeddedProvisioning = [NSString stringWithContentsOfFile:embeddedPath encoding:NSASCIIStringEncoding error:nil];
        // 按行拆分描述文件内容
        NSArray *embeddedProvisioningLines = [embeddedProvisioning componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        // 遍历描述文件的行
        for (int i = 0; i < embeddedProvisioningLines.count; i++) {
            // 检查行是否包含 "application-identifier" 字符串
            if ([[embeddedProvisioningLines objectAtIndex:i] rangeOfString:@"application-identifier"].location != NSNotFound &&
                ((i+1) < embeddedProvisioningLines.count)) {
                // 获取下一行的范围
                NSRange rangePrefix = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"<string>"];
                NSRange rangeSuffix = [[embeddedProvisioningLines objectAtIndex:i+1] rangeOfString:@"</string>"];
                if (rangePrefix.location != NSNotFound && rangeSuffix.location != NSNotFound) {
                    // 获取完整的标识符
                    NSRange range = NSMakeRange(rangePrefix.location+rangePrefix.length, rangeSuffix.location - (rangePrefix.location+rangePrefix.length));
                    NSString *fullIdentifier = [[embeddedProvisioningLines objectAtIndex:i+1] substringWithRange:range];
                    NSLog(@"%@", fullIdentifier);
                    // 拆分标识符为数组
                    NSArray *identifierComponents = [fullIdentifier componentsSeparatedByString:@"."];
                    NSString *appIdentifier = [identifierComponents firstObject];
                    // 比较应用的标识符与给定的团队标识（Team ID）
                    if (![appIdentifier isEqual:teamID]) {
                        return false; // 如果标识符不匹配给定的 Team ID，则返回 false
                    } else {
                        return true; // 如果标识符匹配给定的 Team ID，则返回 true
                    }
                }
            }
        }
    }
    return true; // 如果描述文件不存在或者没有找到相关信息，则默认返回 true
}


@end
