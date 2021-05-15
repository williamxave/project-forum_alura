package br.com.alura.forum.repository;

import java.util.Optional;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit4.SpringRunner;

import br.com.alura.forum.modelo.Curso;

@RunWith(SpringRunner.class)
@DataJpaTest
@AutoConfigureTestDatabase(replace= AutoConfigureTestDatabase.Replace.NONE)
@ActiveProfiles("test")
public class CursoRepositoryTest {
	
	@Autowired
	private CursoRepository repo;
	
	@Autowired
	private TestEntityManager em;

	@Test
	public void deveriaCarregarUmCursoAoBuscarPeloSeuNome() {
			String nomeCurso = "HTML 5";
			Curso html5 = new Curso();
			html5.setNome(nomeCurso);
			html5.setCategoria("Programação");
			em.persist(html5);
	    	Curso curso =  repo.findByNome(nomeCurso); 
	    	Assert.assertNotNull(curso);
	    	Assert.assertEquals(nomeCurso, curso.getNome());
	}
	
	@Test
	public void naoDeveriaCarregarUmCursoNãoCadastrado() {
		String nomeCurso = "JPA";
	    	Curso curso =  repo.findByNome(nomeCurso); 
	    	Assert.assertNotNull(curso);
	    	Assert.assertEquals(nomeCurso, curso.getNome());
	}

}


