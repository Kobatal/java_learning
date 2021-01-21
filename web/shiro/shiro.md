# Shiro

​		Shiro是Apache旗下的一个开源项目，它是一个非常易用的安全框架，提供了包括认证、授权、加密、会话管理等功能，与Spring Security一样属基于权限的安全框架，但是与Spring Security 相比，Shiro使用了比较简单易懂易于使用的授权方式。Shiro属于轻量级框架，相对于Spring Security简单很多，并没有security那么复杂。

![2](https://github.com/Kobatal/java_learning/blob/main/img/2.png)

## 核心组件

### Subject

​		包含 **Principals **和 **Credentials** 两个信息，两者代表了需要认证的内容。

​		**Principals**：代表身份。可以是用户名、邮件、手机号码等等，用来标识一个登录主体的身份。

​		**Credentials**：代表凭证。常见的有密码，数字证书等等。

### SecurityManager

​		这是 Shiro 架构的核心，是 Shiro 内部所有原件的保护伞。项目中一般都会配置 SecurityManager，开发人员将大部分精力放在了 Subject 认证主体上，与 Subject 交互背后的安全操作，则由 SecurityManager 来完成。

### Realm

​		它是连接 Shiro 和具体应用的桥梁。当需要与安全数据交互时，比如用户账户、访问控制等，Shiro 将会在一个或多个 Realm 中查找。我们可以把 Realm 看作 DataSource，即安全数据源。一般，我们会自己定制 Realm。

## 依赖

```java
<dependency>
    <groupId>org.apache.shiro</groupId>
    <artifactId>shiro-spring</artifactId>
    <version>1.3.2</version>
</dependency>
```

# 实体类

```java
package com.besti.qksserver.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import lombok.Data;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.Id;
import java.util.Date;

@Entity
@Data
public class USR extends PK{

    @Id
    @Column(length = 200)
    private String usrname;

    @Column(nullable = false, length = 500)
    private String pwd;

    @Column(nullable = false)
    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss", timezone="GMT+8")
    private Date createtime;

    @Column(nullable = false)
    private Byte role;

    @Column(nullable = true, length = 500)
    private String memo;
}
```

如有需要，可单独建role（角色类）和permissions（权限类）

# DAO

这里主要是为了可以获取用户的角色和权限

```java
package com.besti.qksserver.dao;

import com.besti.qksserver.entity.USR;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * @author Kobatal
 * @date 2021/1/4 11:25
 */
public interface LoginRepository extends JpaRepository<USR,Long> {
    USR findByUsrname(String userName);
}

```

# 自定义Realm

查询用户角色和权限信息，并保存到权限管理器。

```java
package com.besti.qksserver.config;

import com.besti.qksserver.dao.LoginRepository;
import com.besti.qksserver.entity.USR;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.util.StringUtils;
import javax.annotation.Resource;

/**
 * @author Kobatal
 * @date 2020/11/30 10:40
 */
//自定义Realm，用来实现用户认证授权
public class MyShiroRealm extends AuthorizingRealm {

    @Resource
    private LoginRepository loginRepository;

    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        //获取登录用户名
        String name = (String) principalCollection.getPrimaryPrincipal();
        //查询用户名称
        USR user = loginRepository.findByUsrname(name);
        //添加角色和权限
        SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
        //添加角色
        simpleAuthorizationInfo.addRole(String.valueOf(user.getRole()));
//        for (Role role : user.getRoles()) {
//            //添加角色
//            simpleAuthorizationInfo.addRole(role.getRoleName());
            //添加权限
//            for (Permissions permissions : role.getPermissions()) {
//                simpleAuthorizationInfo.addStringPermission(permissions.getPermissionsName());
//            }
//        }
        return simpleAuthorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        if (StringUtils.isEmpty(authenticationToken.getPrincipal())) {
            return null;
        }
        //获取用户信息
        String name = authenticationToken.getPrincipal().toString();
        USR user = loginRepository.findByUsrname(name);
        if (user == null) {
            //这里返回后会报出对应异常
            return null;
        } else {
            //这里验证authenticationToken和simpleAuthenticationInfo的信息
            SimpleAuthenticationInfo simpleAuthenticationInfo = new SimpleAuthenticationInfo(name, user.getPwd(), getName());
            return simpleAuthenticationInfo;
        }
    }
}

```

# ShiroConfig

把自定义Realm和securityManager注入到spring容器中

```java
package com.besti.qksserver.config;

import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Kobatal
 * @date 2020/11/30 10:56
 */
@Configuration
public class ShiroConfig {
    @Bean
    @ConditionalOnMissingBean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator() {
        DefaultAdvisorAutoProxyCreator defaultAAP = new DefaultAdvisorAutoProxyCreator();
        defaultAAP.setProxyTargetClass(true);
        return defaultAAP;
    }

    //将自己的验证方式加入容器
    @Bean
    public MyShiroRealm myShiroRealm() {
        MyShiroRealm myShiroRealm = new MyShiroRealm();
        return myShiroRealm;
    }

    //权限管理，配置主要是Realm的管理认证
    @Bean
    public SecurityManager securityManager() {
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        securityManager.setRealm(myShiroRealm());
        return securityManager;
    }

    //Filter工厂，设置对应的过滤条件和跳转条件
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        shiroFilterFactoryBean.setSecurityManager(securityManager);
        Map<String, String> map = new HashMap<>();
        //登出
        map.put("/logout", "logout");
        //对所有用户认证
        map.put("/**", "authc");
        //登录
        shiroFilterFactoryBean.setLoginUrl("/login");
        //首页
        shiroFilterFactoryBean.setSuccessUrl("/index");
        //错误页面，认证不通过跳转
        shiroFilterFactoryBean.setUnauthorizedUrl("/error");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(map);
        return shiroFilterFactoryBean;
    }


    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}

```

# Controller

```java
package com.besti.qksserver.controller;

import com.besti.qksserver.entity.USR;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Kobatal
 * @date 2021/1/4 11:17
 */
@RestController
public class LoginController {
    @GetMapping("/login")
    public String login(USR user) {
        if (user.getUsrname().isEmpty() || user.getPwd().isEmpty()) {
            return "请输入用户名和密码！";
        }
        //用户认证信息
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(
                user.getUsrname(),
                user.getPwd()
        );
        try {
            //进行验证，这里可以捕获异常，然后返回对应信息
            subject.login(usernamePasswordToken);
//            subject.checkRole("admin");
//            subject.checkPermissions("query", "add");
        } catch (UnknownAccountException e) {
//            log.error("用户名不存在！", e);
            return "用户名不存在！";
        } catch (AuthenticationException e) {
//            log.error("账号或密码错误！", e);
            return "账号或密码错误！";
        } catch (AuthorizationException e) {
//            log.error("没有权限！", e);
            return "没有权限";
        }
        return "login success";
    }

    @RequiresRoles("1")
    @GetMapping("/admin")
    public String admin() {
    //获取用户名
        Subject subject = SecurityUtils.getSubject();
        System.out.println(subject.getPrincipal().toString());
        return "admin success!";
    }

//    @RequiresPermissions("query")
    @GetMapping("/index")
    public String index() {
        return "index success!";
    }

//    @RequiresPermissions("add")
    @GetMapping("/add")
    public String add() {
        return "add success!";
    }
}

```

