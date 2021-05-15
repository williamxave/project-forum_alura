package br.com.alura.forum.controller;


import java.net.URI;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;


@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class AutentificacaoControllerTest {
	
	//Para fazer as requests precisamos do mock ele é tipo um postaman e vai fazer as request para nos 
	//
	@Autowired
	private MockMvc mockMvc;

	@Test
	public void devriaDevolver400CasoDadosDeAutentificacaoEstajamIncorretos() throws Exception {
		
		URI uri =  new URI("/auth"); // Caminho para o nosso controller
		String json =  "{\"email\":\"teste@email.com\", \"senha\": \"123456\"}"; // Corpo da requisicao
			
		mockMvc.perform(MockMvcRequestBuilders   //Monta a request
				.post(uri)	//Pega a uri
				.content(json)	//Recebe o corpo da request
				.contentType(MediaType.APPLICATION_JSON)) // O tipo do conteudo da request
		.andExpect(MockMvcResultMatchers   // Resultadado da request 
				.status()
				.is(400));
		
		
	}

}
