package com.tingfeng.controller;


import com.tingfeng.config.JwtConfig;
import com.tingfeng.model.Person;
import com.tingfeng.model.ReqPerson;
import com.tingfeng.model.Role;
import com.tingfeng.service.PersonService;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

@RestController
public class PersonController {

    @Autowired
    private PersonService personService;

    /**
     * 用户注册
     */
    @PostMapping(value = "/register")
    public String register(@RequestBody() ReqPerson reqPerson) throws ServletException {

        // 检查输入
        if (reqPerson.getUsername() == "" || reqPerson.getUsername() == null || reqPerson.getPassword() == "" || reqPerson.getPassword() == null) {
            throw new ServletException("Username or Password invalid!");
        }

        // 检查用户是否已被注册
        if (personService.findPersonByUsername(reqPerson.getUsername()) != null) {
            throw new ServletException("Username is used!");
        }

        // 默认权限 : MEMBER
        List<Role> roles = new ArrayList<>();
        roles.add(Role.MEMBER);

        // 创建新的 Person 到 ignite DB
        personService.save(new Person(reqPerson.getUsername(), reqPerson.getPassword(), roles));

        return "Register Success!";
    }

    /**
     * 检查用户的登录信息，然后创建并返回给前端 jwt token 令牌
     *
     * @param reqPerson
     * @return jwt token
     * @throws ServletException
     */
    @PostMapping("/login")
    public String login(@RequestBody ReqPerson reqPerson) throws ServletException {

        // 检查输入
        if (reqPerson.getUsername() == "" || reqPerson.getUsername() == null || reqPerson.getPassword() == "" || reqPerson.getPassword() == null) {
            throw new ServletException("Please fill in username and password");
        }

        Person person = personService.findPersonByUsername(reqPerson.getUsername());

        // 检查用户是否存在。密码是否正确
        if (personService.findPersonByUsername(reqPerson.getUsername()) == null || !reqPerson.getPassword().equals(person.getPassword())) {
            throw new ServletException("Please fill in username and password");
        }

        // 创建 Twt token 令牌，将username，roles写入令牌
        String jwtToken = Jwts.builder()
                .setSubject(reqPerson.getUsername())
                .claim("roles", person.getRoles())
                .setIssuedAt(new Date())
                .setExpiration(JwtConfig.EXPIRATION_DATE)
                .signWith(JwtConfig.SIGNATURE_ALGORITHM, JwtConfig.SECRET_KEY)
                .compact();

        return jwtToken;
    }
}
