#include <cstddef>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include <workflow/WFHttpServer.h>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFFacilities.h"

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>

void process_request(WFHttpTask *task, modsecurity::ModSecurity *modsec, modsecurity::RulesSet *rules) {
    auto *req = task->get_req();
    auto *resp = task->get_resp();

    // using modsecurity::RuleMessage; 

    // 创建 ModSecurity 事务
    modsecurity::Transaction transaction(modsec, rules, nullptr);

    // 处理请求头
    protocol::HttpHeaderCursor cursor(req);
    std::string header_name, header_value;
    while (cursor.next(header_name, header_value)) {
        std::cout << header_name.c_str() << ":" << header_value.c_str() << std::endl; 
        transaction.addRequestHeader(header_name.c_str(), header_value.c_str());
    }

    // 处理请求体
    const void *body;
    size_t body_len;
    req->get_parsed_body(&body, &body_len);
    transaction.appendRequestBody((const unsigned char *)body, body_len);

    // 执行请求检测
    auto t_header = transaction.processRequestHeaders(); 

    if ( transaction.processRequestBody() != 0) {
        auto x = transaction.m_id; 
        std::cout << x << "-" << transaction.processRequestHeaders() << "-" << t_header << std::endl; 

        resp->set_status_code("403");
        resp->append_output_body("Request blocked by ModSecurity");
    } else {
        // 如果没有命中规则，返回 200 OK
        resp->set_status_code("200");
        resp->append_output_body("");
    }
}


static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}


int main() {
    // 初始化 ModSecurity
    modsecurity::ModSecurity modsec;
    modsecurity::RulesSet rules;

    // 加载规则文件
    if (rules.loadFromUri("./main.conf") < 0) {
        std::cerr << "Failed to load rules: " << rules.getParserError() << std::endl;
        return 1;
    }

    // 创建 HTTP 服务器
    WFHttpServer server([&modsec, &rules](WFHttpTask *task) {
        process_request(task, &modsec, &rules);
    });

    signal(SIGINT, sig_handler);

    // 监听 8080 端口
    if (server.start(8977) == 0) {
        getchar();  // 按下任意键停止服务器
        server.stop();
    } else {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    return 0;
}
