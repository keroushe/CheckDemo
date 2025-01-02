//
//  ViewController.m
//  CheckDemo
//
//  Created by ijm-ycy on 16.12.21.
//

#import "ViewController.h"
#import "CheckTestOC.h"
#import "CheckDemo-Swift.h"
@import TestFramework;
#import <WebKit/WebKit.h>

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    [CheckTestOC testAll];
    [CheckTest testAll];
    
    /// 注意⚠️， 格式化字符串sscanf
    /*
     // 注意⚠️，下面的这段代码`@available`会调用sscanf,进而会导致格式化字符串漏洞，可通过版本号判断代替
 //    if (@available(iOS 11.0, *)) {
 //        NSLog(@"is ios 11");
 //    }
     ////
     if ([[UIDevice currentDevice].systemVersion floatValue] >= 11) {
         NSLog(@"is ios 11");
     }
     
     // Swift中编译错误，可忽略这个函数风险
 //    if #available(iOS 15.0, *) {
 //        UITableView.appearance().sectionHeaderTopPadding = 0
 //    } else {
 //        // Fallback on earlier versions
 //    }
     */
    // UIWebView跨域访问读取或修改文件的风险, 参考: https://www.jianshu.com/p/87dac1685cdc
//    [self showUIWebViewFile]; // 通过此方式可访问手机任意文件内容
//    [self showWkWebViewFile];
    
    [self addObserverNotification];
}

#if 0
- (void)showUIWebViewFile
{
    UIWebView *webView = [[UIWebView alloc] initWithFrame:CGRectMake(0, 0, [[UIScreen mainScreen] bounds].size.width, [[UIScreen mainScreen] bounds].size.height)];
    [self.view addSubview:webView];

    NSString *filePath = [[NSBundle mainBundle] pathForResource:@"index" ofType:@"html"];
    NSURL *url = [[NSURL alloc] initWithString:filePath];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    [webView loadRequest:request];
}

- (void)showWkWebViewFile
{
    WKWebViewConfiguration *configuration = [[WKWebViewConfiguration alloc] init];
    configuration.preferences.javaScriptEnabled = YES;
    configuration.preferences.javaScriptCanOpenWindowsAutomatically = YES;
    configuration.suppressesIncrementalRendering = YES; // 是否支持记忆读取
   [configuration.preferences setValue:@YES forKey:@"allowFileAccessFromFileURLs"];
    if (@available(iOS 10.0, *)) {
         [configuration setValue:@YES forKey:@"allowUniversalAccessFromFileURLs"];
    }
   WKWebView *wkweb = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:configuration];
   wkweb.center = self.view.center;
   wkweb.UIDelegate = self;//代理，需要实现alert
   [self.view addSubview:wkweb];
   wkweb.backgroundColor = UIColor.redColor;

   NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
   NSString *filePath =[resourcePath stringByAppendingPathComponent:@"index.html"];
   NSMutableString *htmlstring=[[NSMutableString alloc] initWithContentsOfFile:filePath  encoding:NSUTF8StringEncoding error:nil];
   NSURL *baseUrl=[NSURL fileURLWithPath:[[NSBundle mainBundle] bundlePath]];
   [wkweb loadHTMLString:htmlstring baseURL:baseUrl];
}
#endif

- (void)addObserverNotification
{
    if (@available(iOS 11.0, *)) {
        [[NSNotificationCenter defaultCenter] addObserverForName:UIScreenCapturedDidChangeNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
            NSLog(@"接收到UIScreenCapturedDidChangeNotification通知");
        }];
    }
    
    [[NSNotificationCenter defaultCenter] addObserverForName:UIScreenDidConnectNotification object:nil queue:[NSOperationQueue mainQueue] usingBlock:^(NSNotification * _Nonnull note) {
        NSLog(@"接收到UIScreenDidConnectNotification通知");
    }];
}

- (void)dealloc
{
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
