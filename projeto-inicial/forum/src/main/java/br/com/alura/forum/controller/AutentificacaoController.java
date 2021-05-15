package br.com.alura.forum.controller;

import javax.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import br.com.alura.forum.config.security.GeradorDeToken;
import br.com.alura.forum.controller.dto.TokenDto;
import br.com.alura.forum.form.LoginForm;

@RestController
@RequestMapping("/auth")
@Profile("prod")
public class AutentificacaoController {

	@Autowired
	private AuthenticationManager authenticationManager; 
	
	@Autowired
	private GeradorDeToken geradorDeToken;
	

	@PostMapping
	public ResponseEntity<TokenDto> autenticar(@RequestBody @Valid LoginForm loginForm) {
		UsernamePasswordAuthenticationToken dadosLogin = loginForm.converter();
		
		try {
			Authentication authentication = authenticationManager.authenticate(dadosLogin);
			String token = geradorDeToken.gerarToken(authentication);
			return ResponseEntity.ok(new TokenDto(token, "Bearer"));
		} catch (AuthenticationException e) {
			return ResponseEntity.badRequest().build();
		}

	}

}
