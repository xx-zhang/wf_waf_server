#include <cstddef>
#include <memory>
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

#include "nlohmann/json.hpp"


nlohmann::json process_intervention(modsecurity::Transaction *transaction) {
    nlohmann::json reason; 
    reason["transaction_id"] = transaction->m_id; 

    modsecurity::ModSecurityIntervention intervention;
    if (msc_intervention(transaction, &intervention) == 0) {
        // 正常通过，没有拦截
        reason["status_code"] = 200; 
        reason["disruptive"] = false; 
        return reason; 
    }

    if (intervention.log == NULL) {
        intervention.log = strdup("(no log message was specified)");
    }

    // std::cout << "Log: " << intervention.log << std::endl;
    reason["intervention_log"] = std::string(intervention.log) ; 
    free(intervention.log);
    intervention.log = NULL;

    if (intervention.url != NULL) {
        // std::cout << "Intervention, redirect to: " << intervention.url;
        reason["redirect_url"] =  intervention.url ; 
        reason["status_code"] =  302; 
        reason["disruptive"] = false; 
        // std::cout << " with status code: " << intervention.status << std::endl;
        free(intervention.url);
        intervention.url = NULL;
        return reason;
        // return intervention.status;
    }

    if (intervention.status != 200) {
        reason["status_code"] =  intervention.status; 
        reason["disruptive"] = true; 
    }

    return reason;
}


// 非 block 这个逻辑是有效的可以响应任意拦截的详情，否则就似乎拦截的上下文结果。
void process_request(WFHttpTask *task, modsecurity::ModSecurity *modsec, modsecurity::RulesSet *rules) {
    auto *req = task->get_req();
    auto *resp = task->get_resp();
    resp->set_header_pair("Content-Type", "aplication/json");
    nlohmann::json intervention_reason; 
    bool disruptive; 
    int status_code; 

    // 创建 ModSecurity 事务
    auto modsecTransaction = std::make_unique<modsecurity::Transaction>(modsec, rules, nullptr);
    modsecTransaction->processURI(req->get_request_uri(), req->get_method(), "1.1");
    std::this_thread::sleep_for(std::chrono::microseconds(5));
    // 处理并响应 responseBody 
    intervention_reason = process_intervention(modsecTransaction.get());
    disruptive = intervention_reason["disruptive"].get<bool>();
    status_code = intervention_reason["status_code"].get<int>();
    if(disruptive) {
        resp->set_status_code(std::to_string(status_code));
        resp->append_output_body(intervention_reason.dump()); 
        return; 
    }

    auto x = modsec->m_resource_collection;
    // 处理请求头
    protocol::HttpHeaderCursor cursor(req);
    std::string header_name, header_value;
    while (cursor.next(header_name, header_value)) {
        modsecTransaction->addRequestHeader(header_name.c_str(), header_value.c_str());
    } 
    modsecTransaction->processRequestHeaders();
    // 处理并响应 responseBody 
    intervention_reason = process_intervention(modsecTransaction.get());
    disruptive = intervention_reason["disruptive"].get<bool>();
    status_code = intervention_reason["status_code"].get<int>();
    if(disruptive) {
        resp->set_status_code(std::to_string(status_code));
        resp->append_output_body(intervention_reason.dump()); 
        return; 
    }
    // 处理请求体
    const void *body;
    size_t body_len;
    req->get_parsed_body(&body, &body_len);
    modsecTransaction->appendRequestBody((const unsigned char *)body, body_len);
    modsecTransaction->processRequestBody(); 
    // 处理并响应 responseBody 
    intervention_reason = process_intervention(modsecTransaction.get());
    disruptive = intervention_reason["disruptive"].get<bool>();
    status_code = intervention_reason["status_code"].get<int>();
    if(disruptive) {
        resp->set_status_code(std::to_string(status_code));
        resp->append_output_body(intervention_reason.dump()); 
        return; 
    }
    resp->set_status_code("200");
    resp->append_output_body("{\"code\": 0, \"msg\": \"OK\"}"); 
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
    // modsec->setServerLogCb(logCb, modsecurity::RuleMessageLogProperty
    //     | modsecurity::IncludeFullHighlightLogProperty);

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
        std::cout << "start serer in 8977" << std::endl; 
        getchar();  // 按下任意键停止服务器
        server.stop();
    } else {
        std::cerr << "Failed to start server" << std::endl;
        return 1;
    }

    return 0;
}
