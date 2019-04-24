package com.wexinc.interview.challenge1.models;

public class User {
	private int id;
	private String name;
	private String passHash;
	private AccessLevel access;
	private String newPassword;

	public User(int id, String name, String passHash, AccessLevel access) {
		super();
		this.id = id;
		this.name = name;
		this.passHash = passHash;
		this.access = access;
		this.newPassword = newPassword;
	}

	public String getPassHash() {
		return passHash;
	}

	public void setPassHash(String passHash) {
		this.passHash = passHash;
	}

	public AccessLevel getAccess() {
		return access;
	}

	public void setAccess(AccessLevel access) {
		this.access = access;
	}

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getName() {
		return name;
	}

	public String getNewPassword() {
		return newPassword;
	}

	public void setNewPassword(String newPassword) {
		this.newPassword = newPassword;
	}
}
