import { create } from 'zustand'
import { persist, createJSONStorage } from 'zustand/middleware';

type NavbarStore = {
  navOpened: boolean,
  setOpenNav: (opened: boolean) => void,
  closeNav: () => void,
  openNav: () => void,
  toggleNav: () => void,
}

export const useNavbarStore = create<NavbarStore>()((set) => ({
    navOpened: false,
    setOpenNav: (opened: boolean) => set({ navOpened: opened }),
    closeNav: () => set({ navOpened: false }),
    openNav: () => set({ navOpened: true }),
    toggleNav: () => set((state) => ({ navOpened: !state.navOpened })),
}))



interface AuthState {
  access_token: string | null;
  setAccessToken: (token: string | null) => void;
  clearAccessToken: () => void;
  getAccessToken: () => string | null;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      access_token: null,
      setAccessToken: (token) => set({ access_token: token }),
      clearAccessToken: () => set({ access_token: null }),
      getAccessToken: () => get().access_token,
    }),
    {
      name: 'auth-storage',
      storage: createJSONStorage(() => localStorage),
      partialize: (state) => ({ access_token: state.access_token }),
    }
  )
);

// Hook personalizzati per un uso più facile nei componenti
export const useAuth = () => {
  const { access_token, setAccessToken, clearAccessToken, getAccessToken } = useAuthStore();
  
  const isAuthenticated = !!access_token;
  
  return {
    access_token,
    isAuthenticated,
    setAccessToken,
    clearAccessToken,
    getAccessToken,
  };
};

interface SessionState {
  home_section: string | null;
  setHomeSection: (section: string | null) => void;
  getHomeSection: () => string | null;
}

export const useSessionStore = create<SessionState>()(
  persist(
    (set, get) => ({
      home_section: null,
      setHomeSection: (section) => set({ home_section: section }),
      getHomeSection: () => get().home_section,
    }),
    {
      name: 'session-storage',
      storage: createJSONStorage(() => sessionStorage),
      partialize: (state) => ({ home_section: state.home_section }),
    }
  )
);


export const useSession = () => {
  const { home_section, setHomeSection, getHomeSection } = useSessionStore();
  
  return {
    home_section,
    setHomeSection,
    getHomeSection,
  };
};
