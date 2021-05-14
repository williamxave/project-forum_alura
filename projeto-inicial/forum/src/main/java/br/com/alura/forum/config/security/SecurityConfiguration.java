package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private LogicaDeAutentificacao logicaDeAutentificacao;
	
	@Autowired
	private GeradorDeToken geradorDeToken;
	
	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
	
	//Configuracoes de autentificacao
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(logicaDeAutentificacao).passwordEncoder(new BCryptPasswordEncoder());
	}
	
	//Configuracao de autorizacao
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
		.antMatchers(HttpMethod.GET, "/topicos").permitAll()
		.antMatchers(HttpMethod.GET, "/topicos/*").permitAll()
		.antMatchers(HttpMethod.POST, "/auth").permitAll()
		.anyRequest().authenticated()
		.and().csrf().disable() // Desabilita csrf
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Isso diz para o Spring Security que nao é pra criar sessão pq vamos trabalhar com token
		.and().addFilterBefore(new AutentificacaoViaTokenFilter(geradorDeToken), UsernamePasswordAuthenticationFilter.class); // fala pro spring usar primeiro o nosso filtro
	}
	
	//Configuracao de recursos estatico(js,css,imagem,etc)
	@Override
	public void configure(WebSecurity web) throws Exception {
	}
	
	
}
