package com.tingfeng.config;


import com.tingfeng.model.Person;
import com.tingfeng.model.Role;
import com.tingfeng.service.PersonService;
import org.apache.ignite.Ignite;
import org.apache.ignite.Ignition;
import org.apache.ignite.configuration.CacheConfiguration;
import org.apache.ignite.configuration.IgniteConfiguration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

/**
 * Ignite DB 配置项
 */
@Configuration
public class IgniteCfg {

    @Autowired
    PersonService personService;

    /**
     * 初始化ignite节点信息
     *
     * @return Ignite
     */
    @Bean
    public Ignite igniteInstance() {
        // 配置IgniteConfiguration
        IgniteConfiguration cfg = new IgniteConfiguration();

        // 设置节点名称
        cfg.setIgniteInstanceName("springDataNode");

        // 启用Peer类加载器
        cfg.setPeerClassLoadingEnabled(true);

        // 创建一个新的Cache以供Ignite节点使用
        CacheConfiguration ccfg = new CacheConfiguration("PersonCache");

        // 设置SQL的Schema
        ccfg.setIndexedTypes(Long.class, Person.class);

        cfg.setCacheConfiguration(ccfg);

        return Ignition.start(cfg);
    }


    /**
     * Add few people in ignite for testing easily
     */
    @Bean
    public int addPerson() {
        System.out.println("初始化3位用户");

        // Give a default role : MEMBER
        List<Role> roles = new ArrayList<>();
        roles.add(Role.MEMBER);

        // 保存数据
        personService.save(new Person("test1", "test1", roles));
        personService.save(new Person("test2", "test2", roles));

        // 跟第三个用户增加一个admin权限
        roles.add(Role.ADMIN);
        personService.save(new Person("test3", "test3", roles));

        return 0;
    }
}