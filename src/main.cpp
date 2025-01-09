#include <cstddef>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <string>

#include <workflow/WFHttpServer.h>
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFFacilities.h"

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>


// modsecurity::ModSecurity *modsec;
// modsecurity::RulesSet *rules; 
modsecurity::Transaction* transaction; 


void process_request(WFHttpTask *task) {
    using modsecurity::ModSecurity;
    using modsecurity::Rules;
    using modsecurity::Transaction;

    auto *req = task->get_req();
    auto *resp = task->get_resp();

    // 创建 ModSecurity 事务
    // modsecurity::Transaction *transaction = new Transaction(modsec, rules, nullptr);
    // modsecurity::Transaction transaction(modsec, rules, nullptr);

    // 处理请求头
    protocol::HttpHeaderCursor cursor(req);
    std::string header_name, header_value;
    while (cursor.next(header_name, header_value)) {
        transaction->addRequestHeader(header_name.c_str(), header_value.c_str());
    }

    // 处理请求体
    const void *body;
    size_t body_len;
    req->get_parsed_body(&body, &body_len);
    transaction->appendRequestBody((const unsigned char *)body, body_len);

    // 执行请求检测
    if (transaction->processRequestHeaders() != 0 || transaction->processRequestBody() != 0) {
        // 如果检测到攻击，返回阻断响应
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

    modsecurity::ModSecurity* modsec;
    modsecurity::RulesSet*  rules;

    const char* conf_file = "path/to/your/modsecurity.conf"; 
    // 加载规则文件
    if (rules->loadFromUri(conf_file) < 0) {
        std::cerr << "Failed to load rules: " << rules->getParserError() << std::endl;
        return 1;
    }
    transaction =  new modsecurity::Transaction(modsec, rules, nullptr); 

    signal(SIGINT, sig_handler);
	WFHttpServer server(process_request);
    
	if (server.start(8088) == 0)
	{
		wait_group.wait();
		server.stop();
	}
	else
	{
		perror("Cannot start server");
		exit(1);
	}
    

    return 0;
}
