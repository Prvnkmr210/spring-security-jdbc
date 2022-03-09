package com.example.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SpringSecurity extends WebSecurityConfigurerAdapter{
	
	@Override
	public void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.inMemoryAuthentication()
			.withUser("foo")
			.password("foo")
			.roles("USER");
	}
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// http.authorizeRequests(); Authorizes all the request
		http.authorizeRequests()
				.antMatchers("/admin").hasRole("USER")
				.antMatchers("/user").hasRole("USER")
				.antMatchers("/").permitAll()
				.and().formLogin();
	}
	
	@Bean
	public PasswordEncoder getPasswordEncode() {
		return NoOpPasswordEncoder.getInstance();
	}
	
	

}
