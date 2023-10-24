//
//  CheckTestOC.h
//  CheckDemo
//
//  Created by ijiami on 2022/2/18.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/*
 ⚠️⚠️⚠️查找风险对应符号在哪个地方
 先在工程中搜索符号，工程中没有，有可能是第三方库包含了，可以使用nm命令查找在哪个第三方库

 nm -pa <macho文件路径> | grep '符号'
 例如:
 nm -pa AFNetorking.framework/AFNetorking | grep 'UIWebView'
 nm -pa CheckDemo.app/CheckDemo | grep 'UIWebView'
 nm -pa libStatic.a | grep 'UIWebView'
 **/
@interface CheckTestOC : NSObject

+ (void)testAll;

@end

NS_ASSUME_NONNULL_END
