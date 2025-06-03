'use client';

import { createContext, useContext, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { toast } from 'sonner';
import { getProtectedData, isAuthenticated } from '@/services/auth';

interface User {
  id: number;
  email: string;
  username: string;
  profile_picture?: string;
}

interface AuthContextType {
  user: User | null;
  loading: boolean;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType>({
  user: null,
  loading: true,
  checkAuth: async () => {},
});

export const useAuth = () => useContext(AuthContext);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const checkAuth = async () => {
    try {
      if (!isAuthenticated()) {
        setUser(null);
        return;
      }

      const userData = await getProtectedData();
      setUser(userData.user);
    } catch (error) {
      setUser(null);
      toast.error('Authentication failed');
      router.push('/auth');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  return (
    <AuthContext.Provider value={{ user, loading, checkAuth }}>
      {children}
    </AuthContext.Provider>
  );
}
