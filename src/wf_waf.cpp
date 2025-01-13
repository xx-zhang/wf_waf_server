#include <cstddef>
#include <string>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>

#include <workflow/WFHttpServer.h>
#include "modsecurity/rule_message.h"
#include "workflow/HttpMessage.h"
#include "workflow/HttpUtil.h"
#include "workflow/WFHttpServer.h"
#include "workflow/WFFacilities.h"

#include <modsecurity/modsecurity.h>
#include <modsecurity/rules.h>
#include <modsecurity/rules_set.h>
#include <modsecurity/transaction.h>



int process_intervention(modsecurity::Transaction *transaction) {
    modsecurity::ModSecurityIntervention intervention;
    intervention.status = 200;
    intervention.url = NULL;
    intervention.log = NULL;
    intervention.disruptive = 0;

    if (msc_intervention(transaction, &intervention) == 0) {
        return 0;
    }

    if (intervention.log == NULL) {
        intervention.log = strdup("(no log message was specified)");
    }

    std::cout << "Log: " << intervention.log << std::endl;
    free(intervention.log);
    intervention.log = NULL;

    if (intervention.url != NULL) {
        std::cout << "Intervention, redirect to: " << intervention.url;
        std::cout << " with status code: " << intervention.status << std::endl;
        free(intervention.url);
        intervention.url = NULL;
        return intervention.status;
    }

    if (intervention.status != 200) {
        std::cout << "Intervention, returning code: " << intervention.status;
        std::cout << std::endl;
        return intervention.status;
    }

    return 0;
}


void process_request(WFHttpTask *task, modsecurity::ModSecurity *modsec, modsecurity::RulesSet *rules) {
    auto *req = task->get_req();
    auto *resp = task->get_resp();
    
    int intervention_status; 
    // 创建 ModSecurity 事务
    auto modsecTransaction = std::make_unique<modsecurity::Transaction>(modsec, rules, nullptr);
    modsecTransaction->processURI(req->get_request_uri(), req->get_method(), "1.1");
    std::this_thread::sleep_for(std::chrono::microseconds(5));

    // 处理请求头
    protocol::HttpHeaderCursor cursor(req);
    std::string header_name, header_value;
    while (cursor.next(header_name, header_value)) {
        // std::cout << header_name.c_str() << ":" << header_value.c_str() << std::endl; 
        modsecTransaction->addRequestHeader(header_name.c_str(), header_value.c_str());
    } 
    modsecTransaction->processRequestHeaders();
    intervention_status = process_intervention(modsecTransaction.get()); // 开始监控和操作

    // 处理请求体
    const void *body;
    size_t body_len;
    req->get_parsed_body(&body, &body_len);
    modsecTransaction->appendRequestBody((const unsigned char *)body, body_len);
    modsecTransaction->processRequestBody(); 
    intervention_status = process_intervention(modsecTransaction.get()); // 开始监控和操作
    // 类似 apisix 直接给个响应; 
    // modsecTransaction->addResponseHeader("HTTP/1.1", "200 OK");
    // modsecTransaction->processResponseHeaders(200, "HTTP 1.2");
    if( ! intervention_status ){
        modsecTransaction->processLogging() ; // generate default alog 
        resp->set_status_code("200");
        resp->append_output_body(modsecTransaction->m_id + "\r\nrequest passed.\r\n");
        return ; 
    }

    resp->set_status_code(std::to_string(intervention_status).c_str());
    resp->append_output_body(modsecTransaction->m_id + "\r\nrequest rejected.\r\n");
    return ; 

}


static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}


static void logCb(void *data, const void *ruleMessagev) {
    if (ruleMessagev == NULL) {
        std::cout << "I've got a call but the message was null ;(";
        std::cout << std::endl;
        return;
    }

    const modsecurity::RuleMessage *ruleMessage = \
        reinterpret_cast<const modsecurity::RuleMessage *>(ruleMessagev);

    std::cout << "Rule Id: " << std::to_string(ruleMessage->m_rule.m_ruleId);
    std::cout << " phase: " << std::to_string(ruleMessage->getPhase());
    std::cout << std::endl;
    if (ruleMessage->m_isDisruptive) {
        std::cout << " * Disruptive action: ";
        std::cout << modsecurity::RuleMessage::log(*ruleMessage);
        std::cout << std::endl;
        std::cout << " ** %d is meant to be informed by the webserver.";
        std::cout << std::endl;
    } else {
        std::cout << " * Match, but no disruptive action: ";
        std::cout << modsecurity::RuleMessage::log(*ruleMessage);
        std::cout << std::endl;
    }
}

int main() {
    // 初始化 ModSecurity
    auto modsec = std::make_unique<modsecurity::ModSecurity>();
    modsec->setConnectorInformation("ModSecurity-test v0.0.1-alpha" \
        " (ModSecurity test)");
    modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty
        | modsecurity::IncludeFullHighlightLogProperty);

    auto rules = std::make_unique<modsecurity::RulesSet>();
    // 加载规则文件
    if (rules->loadFromUri("./main.conf") < 0) {
        std::cerr << "Failed to load rules: " << rules->getParserError() << std::endl;
        return 1;
    }

    // 创建 HTTP 服务器
    WFHttpServer server([&modsec, &rules](WFHttpTask *task) {
        process_request(task, modsec.get(), rules.get());
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
