package com.iotproject.server.iotserver.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;
import org.springframework.security.web.access.AccessDeniedHandler;


@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {



    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        // add our user for in memory authentication

        auth.inMemoryAuthentication()
                .withUser("John").password("test123").roles("USER")
                .and()
                .withUser("Admin").password("test123").roles("ADMIN");


    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                    .antMatchers("/sensorData", "/sensorData/list", "/sensorData/graphSensorData_1").permitAll()
                //.antMatchers("/sensorData/**").hasRole("ADMIN")
                .anyRequest().authenticated()
                    .and()
                .formLogin()
                    .loginPage("/sensorData/showMyLoginPage")
                    //.loginProcessingUrl("/authenticateTheUser")
                    .permitAll()
                .and()
                .logout()
                    .permitAll();



    }


}