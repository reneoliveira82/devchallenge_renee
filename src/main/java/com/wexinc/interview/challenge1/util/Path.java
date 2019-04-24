package com.wexinc.interview.challenge1.util;

public class Path {
	public static final String ThreadList = "/threads/";
	public static final String OneThread = "/threads/:threadId/";
	public static final String Login = "/login/";
	public static final String UpdatePassword = "/updatepass/";


	public static String getThreadlist() {
		return ThreadList;
	}

	public static String getOnethread() {
		return OneThread;
	}

	public static String getLogin() {
		return Login;
	}

}
