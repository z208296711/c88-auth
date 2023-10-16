package com.c88.auth.security.config;

import cn.hutool.http.HttpStatus;
import cn.hutool.json.JSONUtil;
import com.c88.auth.security.CustomTokenServices;
import com.c88.auth.security.core.clientdetails.ClientDetailsServiceImpl;
import com.c88.auth.security.core.userdetails.affiliate.AffiliateUserDetails;
import com.c88.auth.security.core.userdetails.affiliate.AffiliateUserDetailsServiceImpl;
import com.c88.auth.security.core.userdetails.member.MemberUserDetails;
import com.c88.auth.security.core.userdetails.user.SysUserDetails;
import com.c88.auth.security.core.userdetails.user.SysUserDetailsServiceImpl;
import com.c88.auth.security.extension.affiliate.AffiliateTokenGranter;
import com.c88.auth.security.extension.email.EmailCodeTokenGranter;
import com.c88.auth.security.extension.member.MemberTokenGranter;
import com.c88.auth.security.extension.mobile.SmsCodeTokenGranter;
import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaService;
import com.c88.auth.security.extension.recaptcha.GoogleReCaptchaTokenGranter;
import com.c88.auth.security.extension.refresh.PreAuthenticatedUserDetailsService;
import com.c88.common.core.constant.SecurityConstants;
import com.c88.common.core.result.Result;
import com.c88.common.core.result.ResultCode;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.endpoint.TokenKeyEndpoint;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import java.security.KeyPair;
import java.util.*;

import static com.c88.common.core.constant.SecurityConstants.AFFILIATE_ID;
import static com.c88.common.core.constant.SecurityConstants.MEMBER_ID;

/**
 * 认证授权配置
 */
@Configuration
@RequiredArgsConstructor
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final GoogleReCaptchaService googleReCaptchaService;
    private final ClientDetailsServiceImpl clientDetailsService;
    private final SysUserDetailsServiceImpl sysUserDetailsService;
    private final AffiliateUserDetailsServiceImpl affiliateDetailsService;

    private final AuthenticationManager authenticationManager;
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * OAuth2客户端
     */
    @Override
    @SneakyThrows
    public void configure(ClientDetailsServiceConfigurer clients) {
        clients.withClientDetails(clientDetailsService);
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        List<TokenEnhancer> tokenEnhancerList = new ArrayList<>();
        tokenEnhancerList.add(tokenEnhancer());
        tokenEnhancerList.add(jwtAccessTokenConverter());
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancerList);


        endpoints.accessTokenConverter(jwtAccessTokenConverter())
                .tokenEnhancer(tokenEnhancerChain).authenticationManager(authenticationManager);
        // 获取原有默认授权模式(授权码模式、密码模式、客户端模式、简化模式)的授权者
        List<TokenGranter> granterList = new ArrayList<>(Arrays.asList(endpoints.getTokenGranter()));

        // 添加會員授權者
        granterList.add(new MemberTokenGranter(endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(), authenticationManager, googleReCaptchaService,
                redisTemplate));

        // 添加代理授權者
        granterList.add(new AffiliateTokenGranter(endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(), authenticationManager, googleReCaptchaService,
                redisTemplate));
        // 添加會員手機授權者
        granterList.add(new SmsCodeTokenGranter(endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(), authenticationManager, googleReCaptchaService
        ));
        // 添加會員電子郵件授權者
        granterList.add(new EmailCodeTokenGranter(endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(), authenticationManager, googleReCaptchaService
        ));
//
        // 添加會員授權者
        granterList.add(new GoogleReCaptchaTokenGranter(endpoints.getTokenServices(),
                endpoints.getClientDetailsService(),
                endpoints.getOAuth2RequestFactory(),
                authenticationManager,
                googleReCaptchaService
        ));


        //token存储模式设定 默认为InMemoryTokenStore模式存储到内存中
        endpoints.tokenStore(tokenStore());

        CompositeTokenGranter compositeTokenGranter = new CompositeTokenGranter(granterList);
        endpoints
                .authenticationManager(authenticationManager)
                .accessTokenConverter(jwtAccessTokenConverter())
                .tokenEnhancer(tokenEnhancerChain)
                .tokenGranter(compositeTokenGranter)

                .tokenServices(tokenServices(endpoints))
        ;

    }

    public DefaultTokenServices tokenServices(AuthorizationServerEndpointsConfigurer endpoints) {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        List<TokenEnhancer> tokenEnhancers = new ArrayList<>();
        tokenEnhancers.add(tokenEnhancer());
        tokenEnhancers.add(jwtAccessTokenConverter());
        tokenEnhancerChain.setTokenEnhancers(tokenEnhancers);

        DefaultTokenServices tokenServices = new CustomTokenServices();
        tokenServices.setTokenStore(endpoints.getTokenStore());
        tokenServices.setSupportRefreshToken(true);
        tokenServices.setClientDetailsService(clientDetailsService);
        tokenServices.setTokenEnhancer(tokenEnhancerChain);

        // 多用户体系下，刷新token再次认证客户端ID和 UserDetailService 的映射Map
        Map<String, UserDetailsService> clientUserDetailsServiceMap = new HashMap<>();
        clientUserDetailsServiceMap.put(SecurityConstants.ADMIN_CLIENT_ID, sysUserDetailsService); // 系统管理客户端
        clientUserDetailsServiceMap.put(SecurityConstants.AFFILIATE_CLIENT_ID, affiliateDetailsService); // 代理管理


        // 刷新token模式下，重写预认证提供者替换其AuthenticationManager，可自定义根据客户端ID和认证方式区分用户体系获取认证用户信息
        PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
        provider.setPreAuthenticatedUserDetailsService(new PreAuthenticatedUserDetailsService<>(clientUserDetailsServiceMap));
        tokenServices.setAuthenticationManager(new ProviderManager(Arrays.asList(provider)));

        /** refresh_token有两种使用方式：重复使用(true)、非重复使用(false)，默认为true
         *  1 重复使用：access_token过期刷新时， refresh_token过期时间未改变，仍以初次生成的时间为准
         *  2 非重复使用：access_token过期刷新时， refresh_token过期时间延续，在refresh_token有效期内刷新便永不失效达到无需再次登录的目的
         */
        tokenServices.setReuseRefreshToken(true);
        return tokenServices;

    }

    @Autowired
    RedisConnectionFactory redisConnectionFactory;

    @Bean
    TokenStore tokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    /**
     * Token增强
     */
    public TokenEnhancer tokenEnhancer() {
        return (accessToken, authentication) -> {
            if (authentication.getPrincipal() instanceof SysUserDetails) {
                SysUserDetails securityUser = (SysUserDetails) authentication.getPrincipal();
                Map<String, Object> additionalInformation = new HashMap<>();
                additionalInformation.put("userId", securityUser.getUserId());
                additionalInformation.put("username", securityUser.getUsername());
                additionalInformation.put("deptId", securityUser.getDeptId());
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            } else if (authentication.getPrincipal() instanceof MemberUserDetails) {
                MemberUserDetails memberUserDetails = (MemberUserDetails) authentication.getPrincipal();
                Map<String, Object> additionalInformation = new HashMap<>();
                additionalInformation.put(MEMBER_ID, memberUserDetails.getId());
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            } else if (authentication.getPrincipal() instanceof AffiliateUserDetails) {
                AffiliateUserDetails affiliateUserDetails = (AffiliateUserDetails) authentication.getPrincipal();
                Map<String, Object> additionalInformation = new HashMap<>();
                additionalInformation.put("username", affiliateUserDetails.getUsername());
                additionalInformation.put(AFFILIATE_ID, affiliateUserDetails.getId());
                ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            }
            return accessToken;
        };
    }

    /**
     * 采用RSA加密算法对JWT进行签名
     */
    public JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setKeyPair(keyPair());
        return jwtAccessTokenConverter;
    }

    /**
     * 密钥对
     */
    @Bean
    public KeyPair keyPair() {
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "123456".toCharArray());
        return keyStoreKeyFactory.getKeyPair("jwt", "123456".toCharArray());
    }

    @Bean
    public TokenKeyEndpoint tokenKeyEndpoint() {
        return new TokenKeyEndpoint(jwtAccessTokenConverter());
    }

    /**
     * 自定义认证异常响应数据
     */
    @Bean
    public AuthenticationEntryPoint authenticationEntryPoint() {
        return (request, response, e) -> {
            response.setStatus(HttpStatus.HTTP_OK);
            response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Access-Control-Allow-Origin", "*");
            response.setHeader("Cache-Control", "no-cache");
            Result result = Result.failed(ResultCode.CLIENT_AUTHENTICATION_FAILED);
            response.getWriter().print(JSONUtil.toJsonStr(result));
            response.getWriter().flush();
        };
    }

}
