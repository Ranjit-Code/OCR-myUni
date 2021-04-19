package org.myuniv.system.course.security;

import org.myuniv.system.course.services.UsersService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.servlet.Filter;

@Configuration @EnableWebSecurity public class WebSecurity extends WebSecurityConfigurerAdapter {
    private UsersService          usersService;
    private Environment           environment;
    private BCryptPasswordEncoder encoder;

    @Autowired public WebSecurity(UsersService usersService, Environment environment, BCryptPasswordEncoder encoder) {
        this.usersService = usersService;
        this.environment = environment;
        this.encoder = encoder;
    }

    @Override protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(usersService).passwordEncoder(encoder);
    }

    @Override protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        String registrationUrl = environment.getProperty("api.registration.url.path");
        String loginUrl = environment.getProperty("api.login.url.path");
        http.cors().and()
                .sessionManagement()//
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(getAuthenticationFilter())
                .addFilter(new AuthorizationFilter(authenticationManager(), environment))
                .authorizeRequests().antMatchers(environment.getProperty("api.h2.console.url.path")).permitAll()
                .antMatchers(registrationUrl).permitAll()
                .antMatchers(loginUrl).permitAll()
                .anyRequest().authenticated();
        http.headers().frameOptions().disable();
    }

    private Filter getAuthenticationFilter() {
        AuthenticationFilter filter = null;
        try {
            filter = new AuthenticationFilter(usersService, environment, authenticationManager());
            filter.setFilterProcessesUrl(environment.getProperty("api.login.url.path"));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return filter;
    }

}
