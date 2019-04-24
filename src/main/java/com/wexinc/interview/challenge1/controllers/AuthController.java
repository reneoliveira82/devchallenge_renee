package com.wexinc.interview.challenge1.controllers;

import static com.wexinc.interview.challenge1.util.JsonUtil.json;
import static spark.Spark.post;

import com.google.inject.Guice;
import com.google.inject.Injector;
import com.wexinc.interview.challenge1.AppModule;
import com.wexinc.interview.challenge1.AuthorizationException;
import com.wexinc.interview.challenge1.models.*;
import com.wexinc.interview.challenge1.services.PasswordHasher;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.gson.Gson;
import com.google.inject.Inject;
import com.wexinc.interview.challenge1.repositories.UserRepo;
import com.wexinc.interview.challenge1.services.AuthManager;
import com.wexinc.interview.challenge1.util.AppUtils;
import com.wexinc.interview.challenge1.util.Path;

import spark.Request;
import spark.Response;
import spark.Route;

public class AuthController {
	private UserRepo userRepo;
	private AuthManager authManager;
	private Logger logger;

	@Inject
	public AuthController(AuthManager authManager, UserRepo userRepo) {
		if (authManager == null)
			throw new IllegalArgumentException("AuthManager cannot be null");
		if (userRepo == null)
			throw new IllegalArgumentException("UserRepo cannot be null");

		this.authManager = authManager;
		this.userRepo = userRepo;

		logger = LoggerFactory.getLogger(getClass());

		logger.info("Starting AuthController");

		post(Path.Login, handleLogin, json());

		post(Path.UpdatePassword, updatePassword, json());

	}

	private Route handleLogin = (Request req, Response resp) -> {
		final LoginRequest loginRequest = new Gson().fromJson(req.body(), LoginRequest.class);
		if (loginRequest == null || AppUtils.isNullOrEmpty(loginRequest.getPassword())
				|| AppUtils.isNullOrEmpty(loginRequest.getUserName())) {
			resp.status(400);
			return "";
		}

		final User user = userRepo.getByName(loginRequest.getUserName());

		if (user == null) {
			resp.status(403);
			return "";
		}

		final AuthorizationToken token = authManager.login(user.getId(), loginRequest.getPassword());
		return token.getAuthToken();
	};

	private Route updatePassword = (Request req, Response resp) -> {
		if (!validateAndRotate(req, resp)) return resp.status();


		final User userUpReq = new Gson().fromJson(req.body(), User.class);
		if (userUpReq == null || AppUtils.isNullOrEmpty(userUpReq.getPassHash())
				|| AppUtils.isNullOrEmpty(userUpReq.getName()) || userUpReq.getPassHash().equals(null)) {
			resp.status(400);
			return resp.status();
		}

		final User user = userRepo.getByName(userUpReq.getName());
		if (user == null) {
			resp.status(403);
			return resp.status();
		}


		userUpReq.setId(user.getId());
		String newPass = userUpReq.getNewPassword();
		String oldPass = userUpReq.getPassHash();



		final Injector injector = Guice.createInjector(new AppModule());

		PasswordHasher hasher = injector.getInstance(PasswordHasher.class);
		userUpReq.setPassHash(hasher.hash(newPass, "salt"));


		if(!hasher.hash(oldPass, "salt").equals(user.getPassHash())){
			resp.status(403);
			return resp.status();
		}

		if(newPass.equals(oldPass)){
			resp.status(403);
			return resp.status();
		}

		if(newPass == null || AppUtils.isNullOrEmpty(newPass)){
			resp.status(403);
			return resp.status();
		}

		userRepo.saveUser(userUpReq);
		resp.status(200);

		return resp.status();

	};

	private boolean validateAndRotate(Request req, Response resp) throws AuthorizationException {
		final String authToken = req.headers("X-WEX-AuthToken");
		final AuthorizationToken theToken;
		try{
			theToken = authManager.verifyAuthToken(authToken);
		}catch (AuthorizationException e){
			resp.status(403);
			return false;
		}


        final AuthorizationToken token = authManager.rotateAuthToken(theToken);

		resp.header("X-WEX-AuthToken",token.getAuthToken());
		
		return true;
	}

}
