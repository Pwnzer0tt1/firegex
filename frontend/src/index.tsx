import ReactDOM from 'react-dom/client';
import { BrowserRouter } from "react-router"
import App from './App';
import { MantineProvider } from '@mantine/core';
import { Notifications } from '@mantine/notifications';
import {
  QueryClientProvider,
} from '@tanstack/react-query'
import { queryClient } from './js/utils';
import { CodeHighlightAdapterProvider, stripShikiCodeBlocks } from '@mantine/code-highlight';

import '@mantine/core/styles.css';
import '@mantine/notifications/styles.css';
import '@mantine/code-highlight/styles.css';
import './index.css';
import { CodeHighlightAdapter } from '@mantine/code-highlight/lib/CodeHighlightProvider/CodeHighlightProvider';

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

root.render(
  <QueryClientProvider client={queryClient}>
    <MantineProvider defaultColorScheme='dark'>
      <CodeHighlightAdapterProvider adapter={customShikiAdapter}>
        <Notifications />
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </CodeHighlightAdapterProvider>
    </MantineProvider>
  </QueryClientProvider>
);
