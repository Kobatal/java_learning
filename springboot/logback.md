# Springboot日志管理

## 日志依赖

​		springboot自带**Logback**日志框架，只需要使用**spring-boot-starter**依赖即可。

```pom.xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter</artifactId>
</dependency>
```

## 日志格式

springboot默认日志输出格式

![20180828112411869](https://github.com/Kobatal/java_learning/blob/main/img/20180828112411869.png)

- 日期时间：精确到毫秒
- 日志级别：`ERROR`， `WARN`， `INFO`， `DEBUG` or `TRACE`
- 进程 id
- 分割符：用于区分实际的日志记录
- 线程名：括在方括号中
- 日志名字：通常是源类名
- 日志信息

## 日志级别

日志级别从低到高依次是：`TRACE` < `DEBUG` < `INFO` < `WARN` < `ERROR` < `FATAL`。Logback 日志不提供 FATAL 级别，它被映射到 ERROR 级别。

Spring Boot 只会输出比当前级别高的日志，默认的日志级别是 `INFO`，因此低于 `INFO` 级别的日志记录都不输出。可以在 `application.properties` 配置文件中通过 `logging.level.<logger-name>=<level>` 方式设置日志的级别。

## 日志配置文件

```application.properties
# 启用日志颜色 
spring.output.ansi.enabled=always logging.level.root=INFO 
# mapper 接口所在的包设置为 debug 
logging.level.com.×××.mapper=DEBUG 
# 在当前项目下生成日志文件 
logging.file=./logs/×××.log 
#控制台输出日志格式
logging.pattern.console=%d{yyyy/MM/dd-HH:mm:ss} [%thread] %-5level %clr(%logger){cyan} %clr(%msg%n){green} 
#输出日志文件格式
logging.pattern.file=%d{yyyy/MM/dd-HH:mm} [%thread] %-5level %logger- %msg%n
```

## 代码示例

```java
@SpringBootTest
@RunWith(SpringRunner.class)
public class LoggerTest {

    private static final Logger logger = LoggerFactory.getLogger(LoggerTest.class);

    @Test
    public void test() {
        logger.trace("trace 级别的日志");
        logger.debug("debug 级别的日志");
        logger.info("info 级别的日志");
        logger.warn("warn 级别的日志");
        logger.error("error 级别的日志");
    }
}
```

## 将日志保存进mysql
