#include "modsecurity/rule_message.h"
#include <httplib.h>

#include <memory>
#include <modsecurity/rules_set.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>


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

    httplib::Server svr;
    
    // 设置请求处理器
    svr.Get(".*", [&](const httplib::Request &req, httplib::Response &res) {

        auto modsecTransaction = std::make_unique<modsecurity::Transaction>(modsec.get(), rules.get(), nullptr);

        // 处理请求头
        for (const auto &header : req.headers) {
            modsecTransaction->addRequestHeader(header.first.c_str(), header.second.c_str());
        }
     
        // 处理请求体
        modsecTransaction->appendRequestBody((const unsigned char *)req.body.c_str(), req.body.size());
    
        res.set_header("Connection", "close");
        res.set_header("Accept", "*/*");
        
        
        if (modsecTransaction->processRequestHeaders() !=0 || modsecTransaction->processRequestBody() != 0){
            res.status = 403; 
            res.set_content("forbidden\t\n", "text/plain");
            modsecTransaction->processLogging(); 
            return 0; 
        }
        // 如果没有命中规则，返回 200 OK
        res.status = 200;
        // res.set_content("", "text/plain");
        return 0;
    });

    // 监听 8080 端口
    svr.listen("0.0.0.0", 8288);

    return 0;
}
