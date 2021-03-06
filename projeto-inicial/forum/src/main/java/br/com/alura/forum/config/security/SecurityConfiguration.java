package br.com.alura.forum.config.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
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

import br.com.alura.forum.repository.UsuarioRepository;


@EnableWebSecurity
@Configuration
@Profile(value = {"prod", "test"})
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private LogicaDeAutentificacao logicaDeAutentificacao;
	 
	@Autowired
	private GeradorDeToken geradorDeToken;
	
	@Autowired
	private UsuarioRepository usuarioRepository;
	
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
		.antMatchers(HttpMethod.GET, "/actuator/**").permitAll()
		.antMatchers(HttpMethod.DELETE, "/topicos/*").hasRole("MODERADOR")// Logica de Role s?? ter?? acesso a esse endpoint quem tem o perfil de MODERADOR
		.anyRequest().authenticated()// Essa linha diz que todos os controller que n??o est??o aqui precisam ser autentificados para ser usados
		.and().csrf().disable() // Desabilita csrf
		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // Isso diz para o Spring Security que nao ?? pra criar sess??o pq vamos trabalhar com token
		// fala pro spring usar primeiro o nosso filtro e configura nossa AutentificacaoViaTokenFilter
		//O spring j?? tem um filtro padrao e ele usa sempre ele, precisamos dizer para ele que deve usar o nosso primeiro .addFilterBefore() ai vem o nosso filtro e em seguida
		//o filtro que nos vamos passar na frente que ?? o  padrao do spring UsernamePasswordAuthenticationFilter.class;
		.and().addFilterBefore(new AutentificacaoViaTokenFilter(geradorDeToken, usuarioRepository), UsernamePasswordAuthenticationFilter.class); 
	}
	
	//Configuracao de recursos estatico(js,css,imagem,etc)
	@Override
	public void configure(WebSecurity web) throws Exception {
		    web.ignoring()
		        .antMatchers("/**.html", "/v2/api-docs", "/webjars/**", "/configuration/**", "/swagger-resources/**");
		
	}
	
	
}
