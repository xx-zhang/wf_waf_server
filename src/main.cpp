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

static modsecurity::Transaction* transaction; 


void process_request(WFHttpTask *server_task) {
    auto *req = server_task->get_req();
    auto *resp = server_task->get_resp();
    // long long seq = server_task->get_task_seq();

    protocol::HttpHeaderCursor cursor(req);
    std::string header_name, header_value;
    while (cursor.next(header_name, header_value)) {
        transaction->addRequestHeader(header_name.c_str(), header_value.c_str());
    }

    const void *body;
    size_t body_len;
    req->get_parsed_body(&body, &body_len);
    
    transaction->appendRequestBody((const unsigned char *)body, body_len);

    resp->set_http_version("HTTP/1.1");
	resp->add_header_pair("Content-Type", "text/html");
	resp->add_header_pair("Accept", "*/*");
	resp->add_header_pair("Server", "Sogou WFHttpServer");
    resp->add_header_pair("Connection", "close");

    if (transaction->processRequestHeaders() != 0 || transaction->processRequestBody() != 0) {
        resp->set_status_code("403");
        resp->append_output_body("Request blocked by ModSecurity");
    } else {
        resp->set_status_code("200");
	    resp->set_reason_phrase("OK");
        resp->append_output_body("passed");
    }
}


static WFFacilities::WaitGroup wait_group(1);

void sig_handler(int signo)
{
	wait_group.done();
}

void modsec_transaction_init(modsecurity::Transaction* transaction){
    modsecurity::ModSecurity* modsec;
    modsecurity::RulesSet*  rules;
    const char* conf_file = "./main.conf"; 
    // 加载规则文件
    if (rules->loadFromUri(conf_file) < 0) {
        std::cerr << "Failed to load rules: " << rules->getParserError() << std::endl;
        return ;
    }
    static auto cur_ptr =  new modsecurity::Transaction(modsec, rules, nullptr); 
    transaction = cur_ptr; 
}

int main() {
    // init transaction object 
    modsec_transaction_init(transaction); 

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
