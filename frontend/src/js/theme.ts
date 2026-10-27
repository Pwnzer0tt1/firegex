import { Badge, Card, Checkbox, createTheme, Menu, Modal, Paper, Popover, Table, Tooltip, type MantineColorsTuple } from '@mantine/core'

/**
 * The palette the whole interface is drawn from.
 *
 * It follows the dark scheme of ExploitFarm (the sibling Pwnzer0tt1 tool an A/D team
 * already has open beside this one): true-black surfaces separated by borders rather
 * than by lifted greys, and one saturated colour per meaning. The accent is the
 * orange of the firegex flame instead of ExploitFarm's red, so that red stays free for
 * the one thing it has to mean here — stopped, refused, broken.
 *
 * The same values are exported as CSS custom properties from `index.css` (`--fg-*`);
 * a component styled with plain CSS reads those, one styled through Mantine reads the
 * ramps below, and both end up on the same hex.
 */
export const ACCENT_ORANGE = '#F2954B'
export const DANGER_RED = '#FF5470'
export const SUCCESS_GREEN = '#38C793'
export const WARNING_YELLOW = '#F2B84B'
export const INFO_BLUE = '#5B8DEF'
export const ALT_TEAL = '#4DD0C4'

type Rgb = [number, number, number]
type Hsl = [number, number, number]

function hexToRgb(hex: string): Rgb {
    const n = parseInt(hex.replace('#', ''), 16)
    return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

function rgbToHex(r: number, g: number, b: number): string {
    const channel = (v: number) => Math.max(0, Math.min(255, Math.round(v))).toString(16).padStart(2, '0')
    return `#${channel(r)}${channel(g)}${channel(b)}`.toUpperCase()
}

function rgbToHsl(r: number, g: number, b: number): Hsl {
    r /= 255; g /= 255; b /= 255
    const max = Math.max(r, g, b)
    const min = Math.min(r, g, b)
    const l = (max + min) / 2
    if (max === min) return [0, 0, l]
    const d = max - min
    const s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
    let h: number
    if (max === r) h = (g - b) / d + (g < b ? 6 : 0)
    else if (max === g) h = (b - r) / d + 2
    else h = (r - g) / d + 4
    return [h * 60, s, l]
}

function hslToRgb(h: number, s: number, l: number): Rgb {
    h = ((h % 360) + 360) % 360
    if (s === 0) return [l * 255, l * 255, l * 255]
    const hueToChannel = (p: number, q: number, t: number) => {
        if (t < 0) t += 1
        if (t > 1) t -= 1
        if (t < 1 / 6) return p + (q - p) * 6 * t
        if (t < 1 / 2) return q
        if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6
        return p
    }
    const q = l < 0.5 ? l * (1 + s) : l + s - l * s
    const p = 2 * l - q
    const hk = h / 360
    return [hueToChannel(p, q, hk + 1 / 3) * 255, hueToChannel(p, q, hk) * 255, hueToChannel(p, q, hk - 1 / 3) * 255]
}

/**
 * A ten-step Mantine ramp built from one hex.
 *
 * Mantine paints filled controls in the dark scheme with shade 8 (`primaryShade.dark`
 * below), so the colour as designed sits there exactly. Shade 0 is the same hue a little
 * lighter, which is what `variant="light"` and `"subtle"` use for their text; shade 9 is
 * the hue desaturated and darkened, the tint behind a light badge on a black page.
 * Everything in between is a straight interpolation, so every colour has the same ramp
 * shape and no single one needs tuning by hand.
 */
function shadesFromMain(mainHex: string): MantineColorsTuple {
    const [h, s, l] = rgbToHsl(...hexToRgb(mainHex))
    const lightest = Math.min(0.95, l + 0.086)
    const darkest = Math.max(0.12, l - 0.32)
    const shade = (i: number): string => {
        if (i === 8) return mainHex.toUpperCase()
        if (i === 9) return rgbToHex(...hslToRgb(h, s * 0.32, darkest))
        const t = i / 8
        return rgbToHex(...hslToRgb(h, s, lightest + (l - lightest) * t))
    }
    return Array.from({ length: 10 }, (_, i) => shade(i)) as unknown as MantineColorsTuple
}

/**
 * Neutral surfaces, mapped onto the roles Mantine gives each step in the dark scheme:
 * 0 text, 1 strong secondary text, 2 `c="dimmed"`, 3 placeholders, 4 every default
 * border, 5 hover surfaces, 6 inputs, 7 the body, 8–9 cards and modals.
 *
 * Fills stay at (or within a few units of) black, because on an OLED panel even a small
 * lift reads as a grey patch; borders and hovers are the steps deliberately well above
 * that floor, since a black-on-black layout is told apart by its edges alone.
 */
const DARK: MantineColorsTuple = [
    '#EDEEF0', '#DCDEE2', '#8B909A', '#6B7078', '#2A2C31',
    '#17181A', '#0A0A0B', '#000000', '#070708', '#070708',
]

/** What `color="gray"` resolves to: neutral controls that should not shout. */
const GRAY: MantineColorsTuple = [
    '#C7CAD1', '#ACB0B8', '#8B909A', '#6B7078', '#34363B',
    '#2A2C30', '#1C1E21', '#141517', '#0F1012', '#1E1E1E',
]

export const theme = createTheme({
    primaryColor: 'orange',
    primaryShade: { light: 6, dark: 8 },
    autoContrast: true,
    fontFamily: 'Inter, system-ui, Avenir, Helvetica, Arial, sans-serif',
    fontFamilyMonospace: "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace",
    headings: { fontFamily: 'Inter, system-ui, Avenir, Helvetica, Arial, sans-serif', fontWeight: '650' },
    defaultRadius: 'md',
    radius: { xs: '4px', sm: '6px', md: '8px', lg: '12px', xl: '32px' },
    colors: {
        dark: DARK,
        gray: GRAY,
        orange: shadesFromMain(ACCENT_ORANGE),
        red: shadesFromMain(DANGER_RED),
        green: shadesFromMain(SUCCESS_GREEN),
        lime: shadesFromMain(SUCCESS_GREEN),
        teal: shadesFromMain(ALT_TEAL),
        yellow: shadesFromMain(WARNING_YELLOW),
        blue: shadesFromMain(INFO_BLUE),
        indigo: shadesFromMain('#6F8CEF'),
        cyan: shadesFromMain('#4DC4E0'),
        grape: shadesFromMain('#C061E0'),
        violet: shadesFromMain('#8C6FEF'),
        pink: shadesFromMain('#F25B94'),
    },
    components: {
        Paper: Paper.extend({ defaultProps: { bg: 'dark.8' } }),
        Card: Card.extend({
            defaultProps: { bg: 'dark.8', radius: 'lg', withBorder: true },
            styles: { root: { borderColor: 'var(--fg-border)' } },
        }),
        Modal: Modal.extend({
            defaultProps: { radius: 'lg', overlayProps: { backgroundOpacity: 0.6, blur: 2 } },
            styles: {
                content: { backgroundColor: 'var(--fg-surface)', border: '1px solid var(--fg-border)' },
                header: { backgroundColor: 'var(--fg-surface)' },
            },
        }),
        Menu: Menu.extend({
            styles: { dropdown: { backgroundColor: 'var(--fg-surface)', borderColor: 'var(--fg-border)' } },
        }),
        Popover: Popover.extend({
            styles: { dropdown: { backgroundColor: 'var(--fg-surface)', borderColor: 'var(--fg-border)' } },
        }),
        Tooltip: Tooltip.extend({ defaultProps: { color: 'dark.5' } }),
        Badge: Badge.extend({ defaultProps: { radius: 'xl' } }),
        Table: Table.extend({
            defaultProps: { verticalSpacing: 'sm', horizontalSpacing: 'md' },
            styles: { table: { '--table-border-color': 'var(--fg-border)' } },
        }),
        // An unchecked box is nothing but its border, so it keeps a brighter one than a
        // panel edge does or it reads as empty space rather than as a control.
        Checkbox: Checkbox.extend({ styles: { input: { borderColor: 'var(--mantine-color-dark-2)' } } }),
    },
})
