import ReactDOM from 'react-dom/client';
import { BrowserRouter } from "react-router"
import App from './App';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import {
  QueryClientProvider,
} from '@tanstack/react-query'
import { queryClient } from './js/utils';
import { CodeHighlightAdapterProvider, stripShikiCodeBlocks, CodeHighlightAdapter } from '@mantine/code-highlight';

import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import '@mantine/code-highlight/styles.css';
import './index.css';


const root = ReactDOM.createRoot(
  document.getElementById('root') as HTMLElement
);

// Shiki requires async code to load the highlighter
async function loadShiki() {
  const { createHighlighter } = await import('shiki');
  const shiki = await createHighlighter({
    langs: ['python'],
    themes: ['one-dark-pro', 'one-light']
  });

  return shiki;
}

// Pass this adapter to CodeHighlightAdapterProvider component
export const customShikiAdapter: CodeHighlightAdapter = {
  // loadContext is called on client side to load shiki highlighter
  // It is required to be used if your library requires async initialization
  // The value returned from loadContext is passed to createHighlighter as ctx argument
  loadContext: loadShiki,

  getHighlighter: (ctx) => {
    if (!ctx) {
      return ({ code }) => ({ highlightedCode: code, isHighlighted: false });
    }

    return ({ code, language, colorScheme }) => ({
      isHighlighted: true,
      // stripShikiCodeBlocks removes <pre> and <code> tags from highlighted code
      highlightedCode: stripShikiCodeBlocks(
        ctx.codeToHtml(code, {
          lang: language,
          theme: colorScheme === 'dark' ? 'one-dark-pro' : 'one-light',
        })
      ),
    });
  },
};

import { createTheme } from '@mantine/core';

const myTheme = createTheme({
  fontFamily: 'Inter, sans-serif',
  headings: { fontFamily: 'Hanken Grotesk, sans-serif' },
  primaryColor: 'cyan',
  colors: {
    dark: [
      '#f5f5f5', // 0: text
      '#9aa0a6', // 1: text-secondary
      '#5f6368', // 2: outline
      '#3c4043', // 3: outline-variant
      '#2c2c2f', // 4: surface-variant / fourth_color
      '#1e1e20', // 5: surface-container-high / third_color
      '#1a1a1c', // 6: surface-container
      '#161618', // 7: surface-container-low / primary_color
      '#0a0a0c', // 8: background / secondary_color
      '#050505', // 9: surface-container-lowest
    ],
    cyan: [
      '#e0ffff',
      '#b3fbff',
      '#80f6ff',
      '#4df0ff',
      '#20ebff',
      '#00e5ff', // 5: surface-tint / accent
      '#00b8cc',
      '#008f9f',
      '#006975',
      '#004f59',
    ]
  },
  components: {
    AppShell: {
      styles: {
        root: {
          backgroundColor: '#0a0a0c',
        },
        navbar: {
          backgroundColor: '#161618',
          borderRight: '1px solid #2c2c2f',
        },
        header: {
          backgroundColor: '#161618',
          borderBottom: '1px solid #2c2c2f',
        }
      }
    },
    Card: {
      defaultProps: {
        bg: '#1e1e20',
        radius: 'md',
        withBorder: true,
      },
      styles: {
        root: {
          borderColor: '#2c2c2f',
        }
      }
    }
  }
});

root.render(
  <QueryClientProvider client={queryClient}>
    <MantineProvider defaultColorScheme='dark' theme={myTheme}>
      <CodeHighlightAdapterProvider adapter={customShikiAdapter}>
        <Notifications />
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </CodeHighlightAdapterProvider>
    </MantineProvider>
  </QueryClientProvider>
);
