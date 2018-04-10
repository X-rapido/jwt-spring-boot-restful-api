package com.tingfeng.controller;

import io.jsonwebtoken.Claims;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * 测试JWT，如果验证成功直接返回数据，否则会被过滤器拦截
 */
@RestController
@RequestMapping("/secure")
public class SecureController {

    @RequestMapping("/users/user")
    public String loginSuccess() {
        return "Login Successful!";
    }

    @PostMapping("/user/roles")
    public Object checkRoles(HttpServletRequest request) {
        // 从token中获取用户角色
        Claims claims = request.getAttribute("claims") != null ? (Claims) request.getAttribute("claims") : null;
        return claims.get("roles");
    }

}