import React, { createContext, useContext, useEffect, useState } from "react";
import { apiRequest, getStoredToken, setStoredToken } from "../services/api";
import { User } from "../types";

interface AuthContextValue {
  user: User | null;
  loading: boolean;
  canMutate: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (payload: {
    name: string;
    email: string;
    password: string;
    department?: string;
  }) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  const refreshUser = async () => {
    const token = getStoredToken();
    if (!token) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      const res = await apiRequest<{ user: User }>("/api/auth/me");
      setUser(res.user);
    } catch {
      setStoredToken(null);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refreshUser();
  }, []);

  const login = async (email: string, password: string) => {
    const res = await apiRequest<{ user: User; token: string }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    });
    setStoredToken(res.token);
    setUser(res.user);
  };

  const register = async (payload: {
    name: string;
    email: string;
    password: string;
    department?: string;
  }) => {
    const res = await apiRequest<{ user: User; token: string }>(
      "/api/auth/register",
      {
        method: "POST",
        body: JSON.stringify(payload),
      }
    );
    setStoredToken(res.token);
    setUser(res.user);
  };

  const logout = async () => {
    try {
      await apiRequest("/api/auth/logout", { method: "POST" });
    } catch {
      // Ignore logout transport errors
    } finally {
      setStoredToken(null);
      setUser(null);
    }
  };

  const canMutate = user?.role === "ADMIN" || user?.role === "ANALYST";
  const isAdmin = user?.role === "ADMIN";

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        canMutate,
        isAdmin,
        login,
        register,
        logout,
        refreshUser,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used inside AuthProvider");
  }
  return ctx;
}
