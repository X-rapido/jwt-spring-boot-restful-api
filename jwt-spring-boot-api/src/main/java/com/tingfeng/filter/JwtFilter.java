package com.tingfeng.filter;

import com.tingfeng.config.JwtConfig;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureException;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * JWT 过滤器
 */
public class JwtFilter extends GenericFilterBean {

    @Override
    public void doFilter(final ServletRequest req, final ServletResponse res, final FilterChain chain)
            throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) req;
        final HttpServletResponse response = (HttpServletResponse) res;

        //从Http请求获取授权
        final String authHeader = request.getHeader("authorization");

        // 如果Http请求是OPTIONS，那么只需返回状态码200，即代码中的HttpServletResponse.SC_OK
        // 除OPTIONS外，其他请求应由JWT检查
        if ("OPTIONS".equals(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);

            chain.doFilter(req, res);
        } else {

            // Check the authorization, check if the token is started by "Bearer "
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                throw new ServletException("Missing or invalid Authorization header");
            }

            // 然后从授权中获取JWT令牌
            final String token = authHeader.substring(7);

            try {
                // 使用JWT解析器检查签名是否对密钥“secretkey”有效
                final Claims claims = Jwts.parser().setSigningKey(JwtConfig.SECRET_KEY).parseClaimsJws(token).getBody();

                System.out.println("claims: " + claims);

                // Add the claim to request header
                request.setAttribute("claims", claims);
            } catch (final SignatureException e) {
                throw new ServletException("Invalid token");
            }

            chain.doFilter(req, res);
        }
    }
}
