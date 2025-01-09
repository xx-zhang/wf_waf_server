#include <httplib.h>


#include <modsecurity/rules_set.h>
#include <modsecurity/modsecurity.h>
#include <modsecurity/transaction.h>

int main() {
    // 初始化 ModSecurity
    modsecurity::ModSecurity modsec;
    modsecurity::RulesSet rules;

    // 加载规则文件
    if (rules.loadFromUri("./main.conf") < 0) {
        std::cerr << "Failed to load rules: " << rules.getParserError() << std::endl;
        return 1;
    }

    // 创建 ModSecurity 事务
    modsecurity::Transaction transaction(&modsec, &rules, nullptr);

    // 创建 HTTP 服务器
    httplib::Server svr;

    // 设置请求处理器
    svr.Get(".*", [&](const httplib::Request &req, httplib::Response &res) {

        // 处理请求头
        for (const auto &header : req.headers) {
            transaction.addRequestHeader(header.first.c_str(), header.second.c_str());
        }

        // 处理请求体
        transaction.appendRequestBody((const unsigned char *)req.body.c_str(), req.body.size());

        res.set_header("Connection", "close");
        res.set_header("Accept", "*/*");

        // 执行请求检测
        if (transaction.processRequestHeaders() != 0 || transaction.processRequestBody() != 0) {
            // 如果检测到攻击，返回阻断响应
            res.status = 403;
            res.set_content("Request blocked by ModSecurity", "text/plain");
            return;
        }

        // 如果没有命中规则，返回 200 OK
        res.status = 200;
        res.set_content("", "text/plain");
    });

    // 监听 8080 端口
    svr.listen("0.0.0.0", 8288);

    return 0;
}
