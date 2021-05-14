package br.com.alura.forum.config.security;

import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

import br.com.alura.forum.modelo.Usuario;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class GeradorDeToken {
	
	//Metodos para pegar o time e a senha no properties
	
	@Value("${forum.jwt.expiration}")
	private String expiration;
	
	@Value("${forum.jwt.secret}")
	private String secret;
	
	//Cria o token
	public String gerarToken(Authentication authentication) {
		Usuario logado =  (Usuario) authentication.getPrincipal();  // Pega o user logado, retorna um optional por isso o cast
		Date hoje = new Date();
		Date dataExpiracao = new Date(hoje.getTime() + Long.parseLong(expiration));
		return Jwts.builder()
				.setIssuer("API do Fórum da Alura")
				.setSubject(logado.getId().toString())
				.setIssuedAt(hoje)//  Data da criacao do token
				.setExpiration(dataExpiracao)// Data da expiracao do token
				.signWith(SignatureAlgorithm.HS256, secret) // criptocrafa 
				.compact();
			}

	//Verifica se esse Token é valido
	// O parser elerecebe o token descriptografa e verifica se é valido
	//Chave que ele usa pra criptografar e descriptografar
	//parseClaimsJws(token) retorna as informações dentro do token precisa por dentro de um try catch pq se o token for nullo joga uma exception
	public boolean isTokenValid(String token) {
		try {
			Jwts.parser().setSigningKey(this.secret).parseClaimsJws(token);
			return true;
		} catch (Exception e) {
			return false;
		}
		
	}
}