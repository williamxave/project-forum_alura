package br.com.alura.forum.config.security;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import br.com.alura.forum.modelo.Usuario;
import br.com.alura.forum.repository.UsuarioRepository;

//Classe que vai mandar o token do usuário para o cabeçalho das requisições
//PRECISAMOS FALAR PARA O SPRING SOBRE ESSA CLASSE E NAO É COM ANOTAÇÃO, VAMOS FAZER ISSO LA NA SecurityConfiguration
//Em classe filters nao podemos usar o @Autowired
//Não podemos injetar nada nessa classe então colocamos no construtor os atributos e quem der new na classe já instancia pra nos
//E quem ta fazendo isso é a classe SecurityConfiguration e lá conseguimos instancia ele FON;
public class AutentificacaoViaTokenFilter extends OncePerRequestFilter {

	private UsuarioRepository repo;
	
	private GeradorDeToken geradorDeToken;
	
	
	public AutentificacaoViaTokenFilter(GeradorDeToken geradorDeToken,UsuarioRepository repo) {
		this.geradorDeToken = geradorDeToken;
		this.repo = repo;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String token = recuperToken(request);
		boolean valido = geradorDeToken.isTokenValid(token);
		if(valido) {
			autenticarCliente(token);
		}
		filterChain.doFilter(request, response);
	}

	//Se o usuário for válido, precisamos liberar o acesso pra ele, e vamos falar isso pro Spring com esse método
	private void autenticarCliente(String token) {
		//Para pegar o usuario que está logado precisamos pegar o id dele que está junto com o token
		// que setamos la na classe GeradorDeToken nessa parte .setSubject(logado.getId().toString()); então temos o id do user dentro do token 
		//agora é so chamar ele do banco e xablau.
		
		//Metodo que vai pegar nosso user do banco com o token de parametro
		Long idUsuario = geradorDeToken.getIdUsuario(token);
		//O finfiByid retorna um optional entao precisamos usar o .get() para pegar o obj retornado
		Usuario usuario = repo.findById(idUsuario).get();
		
		//usuario.getAuthorities() retorna os perfis de acesso do nosso usuário
		UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null, usuario.getAuthorities());
		
		//Metodo estático do spring para falar pra ele considere o cara autentificado e deixa ele passar
		//setAuthentication recebe as info do usuário logado
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
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
