package com.c88.auth.security.config;

import com.c88.auth.security.extension.affiliate.AffiliateDaoAuthenticationProvider;
import com.c88.auth.security.extension.email.EmailAuthenticationProvider;
import com.c88.auth.security.extension.member.MemberDaoAuthenticationProvider;
import com.c88.auth.security.extension.mobile.CodeAuthenticationProvider;
import com.c88.common.redis.utils.RedisUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@Slf4j
@RequiredArgsConstructor
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService sysUserDetailsService;
    private final UserDetailsService memberUserDetailsService;
    private final UserDetailsService affiliateUserDetailsService;
    private final RedisUtils redisUtils;

    @Override
    public void configure(AuthenticationManagerBuilder auth) {
        /**
         * 因為 MemberToken 繼承 UsernamePasswordAuthenticationToken，
         * 需要先判斷 memberAuthenticationProvider，才不會被 DaoAuthenticationProvider 統一適用。
         * 參考：{@link MemberDaoAuthenticationProvider#supports(Class)}
         */
        auth.authenticationProvider(memberAuthenticationProvider())
                .authenticationProvider(codeAuthenticationProvider())
                .authenticationProvider(emailAuthenticationProvider())
                .authenticationProvider(daoAuthenticationProvider())
                .authenticationProvider(affiliateAuthenticationProvider())
        ;
    }

    /**
     * 會員驗證提供者
     *
     * @return
     */
    @Bean
    public MemberDaoAuthenticationProvider memberAuthenticationProvider() {
        MemberDaoAuthenticationProvider provider = new MemberDaoAuthenticationProvider();
        provider.setUserDetailsService(memberUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setHideUserNotFoundExceptions(false); // 是否隐藏用户不存在异常，默认:true-隐藏；false-抛出异常；
        return provider;
    }

    /**
     * 後台管理者驗證提供者
     *
     * @return
     */
    @Bean
    public AffiliateDaoAuthenticationProvider affiliateAuthenticationProvider() {
        AffiliateDaoAuthenticationProvider provider = new AffiliateDaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(affiliateUserDetailsService);
        provider.setRedisUtils(redisUtils);// 是否隐藏用户不存在异常，默认:true-隐藏；false-抛出异常；
        return provider;
    }

    /**
     * 後台管理者驗證提供者
     *
     * @return
     */
    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(sysUserDetailsService);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setHideUserNotFoundExceptions(false); // 是否隐藏用户不存在异常，默认:true-隐藏；false-抛出异常；
        return provider;
    }

    @Bean
    public EmailAuthenticationProvider emailAuthenticationProvider() {
        EmailAuthenticationProvider provider = new EmailAuthenticationProvider();
        provider.setUserDetailsService(memberUserDetailsService);
        provider.setRedisUtils(redisUtils);
        return provider;
    }

    @Bean
    public CodeAuthenticationProvider codeAuthenticationProvider() {
        CodeAuthenticationProvider provider = new CodeAuthenticationProvider();
        provider.setUserDetailsService(memberUserDetailsService);
        provider.setRedisUtils(redisUtils);
        return provider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests().antMatchers("/oauth/**", "/sms-code").permitAll()
                // @link https://gitee.com/xiaoym/knife4j/issues/I1Q5X6 (接口文档knife4j需要放行的规则)
                .antMatchers("/actuator/**").permitAll()
                .antMatchers("/webjars/**", "/doc.html", "/swagger-resources/**", "/v2/api-docs").permitAll()
                .antMatchers("/webjars/**", "/doc.html", "/swagger-resources/**", "/v3/api-docs").permitAll()
                .anyRequest().authenticated()
                .and()
                .csrf().disable();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
