import { api } from "./api.js";

export async function me(){
  try { return (await api("/api/auth/me")).user; } catch { return null; }
}

export async function login(email, password){
  return (await api("/api/auth/login", { method:"POST", body: JSON.stringify({ email, password }) })).user;
}

export async function logout(){
  await api("/api/auth/logout", { method:"POST" });
}
