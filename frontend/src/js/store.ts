import { create } from 'zustand'

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
