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

interface SystemState {
  version: string | null;
  setVersion: (version: string | null) => void;
  authDisabled: boolean;
  setAuthDisabled: (authDisabled: boolean) => void;
  /**
   * Whether the live channel is up. It is the only thing that refreshes what the page
   * shows (`staleTime` is infinite), so a page that lost it is a page showing the past,
   * and the sidebar says so.
   */
  socketConnected: boolean;
  /** Tells "still connecting" apart from "was connected and lost it". */
  socketEverConnected: boolean;
  setSocketConnected: (connected: boolean) => void;
}

export const useSystemStore = create<SystemState>()((set) => ({
  version: null,
  setVersion: (version) => set({ version }),
  authDisabled: false,
  setAuthDisabled: (authDisabled) => set({ authDisabled }),
  socketConnected: false,
  socketEverConnected: false,
  setSocketConnected: (connected) => set((state) => ({
    socketConnected: connected,
    socketEverConnected: state.socketEverConnected || connected,
  })),
}));

interface ProblemStripState {
  /**
   * Problems the operator closed, by key. A key carries the state it was raised for
   * (see `components/Shell/problems.ts`), so a dismissal silences that one situation
   * and the same service going wrong in a new way is shown again.
   */
  dismissed: string[];
  dismiss: (key: string) => void;
  /** Dismiss every problem currently shown, in one go. */
  dismissAll: (keys: string[]) => void;
  /** Put a dismissed problem back among the floating cards. */
  restore: (key: string) => void;
  restoreAll: () => void;
  /** Whether the summary of every problem is open. Shared so a card can open it too. */
  summaryOpen: boolean;
  setSummaryOpen: (open: boolean) => void;
}

/** Kept per browser tab: a dismissal is about what this operator has already seen. */
export const useProblemStripStore = create<ProblemStripState>()(
  persist(
    (set) => ({
      dismissed: [],
      // Bounded, so a long round of dismissals cannot grow the stored list forever.
      dismiss: (key) => set((state) => ({ dismissed: [...state.dismissed.filter(k => k !== key), key].slice(-200) })),
      dismissAll: (keys) => set((state) => ({
        dismissed: [...state.dismissed.filter(k => !keys.includes(k)), ...keys].slice(-200),
      })),
      restore: (key) => set((state) => ({ dismissed: state.dismissed.filter(k => k !== key) })),
      restoreAll: () => set({ dismissed: [] }),
      summaryOpen: false,
      setSummaryOpen: (open) => set({ summaryOpen: open }),
    }),
    {
      name: 'problem-strip',
      storage: createJSONStorage(() => sessionStorage),
      // Only the dismissals outlive a reload; an open panel does not.
      partialize: (state) => ({ dismissed: state.dismissed }),
    }
  )
);

interface ProblemPrefsState {
  /**
   * Whether the problem strip is drawn over the page at all. Off, problems are only
   * counted on the bell and listed in its summary: for an operator who checks them
   * there and wants the whole screen for the page.
   */
  showStrip: boolean;
  setShowStrip: (show: boolean) => void;
}

/** Kept per browser across reloads: it is a preference about this screen, not a dismissal. */
export const useProblemPrefsStore = create<ProblemPrefsState>()(
  persist(
    (set) => ({
      showStrip: true,
      setShowStrip: (show) => set({ showStrip: show }),
    }),
    {
      name: 'problem-prefs',
      storage: createJSONStorage(() => localStorage),
    }
  )
);
