package com.tingfeng;

import com.tingfeng.filter.JwtFilter;
import org.apache.ignite.springdata.repository.config.EnableIgniteRepositories;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

/**
 * 该项目是用于将Ignite部署到SpringBoot上的一个测试性的项目
 * 目前的功能包含：
 * 	1. 启动并使用一个ignite节点
 * 	2. 提供api接口实现RESTful的设计，能够通过api添加与查询Cache中的相关内容
 *
 */
@SpringBootApplication
@EnableIgniteRepositories
public class AppRun {

	/**
	 * JWT 过滤器配置
	 */
	@Bean
	public FilterRegistrationBean jwtFilter() {
		final FilterRegistrationBean registrationBean = new FilterRegistrationBean();
		registrationBean.setFilter(new JwtFilter());
		registrationBean.addUrlPatterns("/secure/*");
		return registrationBean;
	}


	public static void main(String[] args) {
		SpringApplication.run(AppRun.class, args);
	}
}
