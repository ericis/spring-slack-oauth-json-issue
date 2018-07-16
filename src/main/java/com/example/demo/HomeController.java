package com.example.demo;

import java.security.Principal;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

	@GetMapping("/user2")
	public Principal home(final Principal principal) {
		return principal;
	}
}
