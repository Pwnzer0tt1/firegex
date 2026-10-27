import { ReactNode, useEffect } from 'react';
import { useLocation } from 'react-router';
import { getMainPath, HOME_SECTIONS } from '../js/utils';
import { useSessionStore } from '../js/store';
import ProblemNotifier from './Services/ProblemNotifier';
import { servicesQuery } from './Services/utils';
import ProblemStrip from './Shell/ProblemStrip';
import { problemsOf } from './Shell/problems';
import Sidebar from './Shell/Sidebar';

/**
 * The frame every page is drawn in: the sidebar on the left, the problem strip across
 * the top of the main column, and the page under it.
 *
 * The services list is read here once and handed to both, because the two must agree
 * — a service marked red in the sidebar with nothing said in the strip is exactly the
 * kind of disagreement that makes an operator distrust both.
 */
function MainLayout({ children }: { children: ReactNode }) {
  const { setHomeSection } = useSessionStore()
  const location = useLocation()
  const list = servicesQuery()
  const services = Array.isArray(list.data) ? list.data : []

  useEffect(() => {
    // Only a page that exists is worth coming back to: "/" redirects to it.
    if (HOME_SECTIONS.includes(getMainPath())) {
      setHomeSection(getMainPath())
    }
  }, [location.pathname])

  return <div className="fg-app">
    <Sidebar services={services} />
    <ProblemNotifier />
    <main className="fg-main">
      <ProblemStrip problems={problemsOf(services)} />
      <div className="fg-page">
        {children}
      </div>
    </main>
  </div>
}

export default MainLayout;
