package com.iotproject.server.iotserver.security;


import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;



@Configuration
@EnableWebSecurity
public class DemoSecurityConfig extends WebSecurityConfigurerAdapter {



    protected void configure(AuthenticationManagerBuilder auth) throws Exception {


        auth.inMemoryAuthentication()
                .withUser("user").password("{noop}password").roles("USER")
                .and()
                .withUser("Adam").password("{noop}test123").roles("ADMIN");


    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable().authorizeRequests()
                .antMatchers("/sensorData/showMyLoginPage").permitAll()
                .antMatchers("/sensorData/**").hasRole("ADMIN")
                .antMatchers("/**").hasRole("MANAGER")
                .anyRequest().authenticated()
                    .and()
                .formLogin()
                .loginProcessingUrl("/sensorData/list") // Submit URL
                    .loginPage("/sensorData/showMyLoginPage")
                    .defaultSuccessUrl("/sensorData/list", true)

                    .permitAll()
                .and()
                .logout()
                .permitAll();


    }


}