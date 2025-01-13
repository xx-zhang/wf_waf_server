# Modecurity 代码解读
```
ModSecurity   //类是整个库的入口点，它负责创建新的Transaction对象。
    | 
    +--> Transaction  // 对象在不同处理阶段会使用RuleSets对象中的规则来评估HTTP事务。
            | 
            +--> RuleSets
                    |
                    +--> Rules // 对象定义了具体的规则逻辑，当规则被触发时，会通过Transaction对象生成一个Intervention对象来表示干预措施。
            |
            +--> Intervention
```

```
1. Transaction
Transaction对象表示一个HTTP事务，它包含了与请求和响应相关的所有信息。Transaction对象的主要职责是执行各个阶段的处理（如连接处理、URI处理、请求头处理等），并应用规则来检查和干预HTTP事务。

主要方法：
processConnection(const std::string& client, const std::string& server): 处理连接阶段。
processURI(const std::string& uri, const std::string& protocol): 处理URI阶段。
processRequestHeaders(): 处理请求头阶段。
processRequestBody(): 处理请求体阶段。
processResponseHeaders(): 处理响应头阶段。
processResponseBody(): 处理响应体阶段。
processLogging(): 处理日志记录阶段。
intervention(Intervention *it): 检查事务是否需要干预。


2. RuleSets
RuleSets对象表示一组规则集合。它包含了多个Rules对象，并负责管理这些规则的加载和执行。

主要方法：
loadFromUri(const std::string& uri): 从URI加载规则。
loadFromString(const std::string& rules): 从字符串加载规则。
3. Rules
Rules对象表示单个规则。每个规则定义了在特定条件下应该执行的操作。规则可以包括各种检查条件和对应的动作（如阻止请求、记录日志等）。

主要方法：
evaluate(Transaction *transaction): 在事务上评估规则。
4. Intervention
Intervention对象表示一个干预操作。当一个规则触发时，Transaction对象可以创建一个Intervention对象来表示需要采取的干预措施。

主要属性和方法：
status: 干预的状态码。
url: 干预后重定向的URL。
log: 干预的日志信息。



AuditLog: 用于处理审计日志的类。

Collection: 用于管理事务中的数据集合。
```
