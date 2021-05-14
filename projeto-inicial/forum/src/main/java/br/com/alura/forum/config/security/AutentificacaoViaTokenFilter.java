package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;

//Classe que vai mandar o token do usuário para o cabeçalho das requisições
//PRECISAMOS FALAR PARA O SPRING SOBRE ESSA CLASSE E NAO É COM ANOTAÇÃO, VAMOS FAZER ISSO LA NA SecurityConfiguration
//Em classe filters nao podemos usar o @Autowired
public class AutentificacaoViaTokenFilter extends OncePerRequestFilter {

	
	private GeradorDeToken geradorDeToken;
	
	
	public AutentificacaoViaTokenFilter(GeradorDeToken geradorDeToken) {
		this.geradorDeToken = geradorDeToken;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String token = recuperToken(request);
		boolean valido = geradorDeToken.isTokenValid(token);
		System.out.println(valido);
		filterChain.doFilter(request, response);

	}

	private String recuperToken(HttpServletRequest request) {

		String pegarTokenDoHeader = request.getHeader("Authorization");
		//startsWith verifica se o cabeçalho comeca com Bearer
		if (pegarTokenDoHeader == null || pegarTokenDoHeader.isEmpty() || !pegarTokenDoHeader.startsWith("Bearer ")) {
			return null;
		}
		//Como o Bearer vem antes do token e sao separados apenas com espaço vamos usar o substring para pegar somente o token
		return pegarTokenDoHeader.substring(7,pegarTokenDoHeader.length());
	}

}
