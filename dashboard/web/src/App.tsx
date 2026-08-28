import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";

import { AppShell } from "./components/AppShell";
import { LoadingState } from "./components/States";

const OverviewPage = lazy(() =>
  import("./pages/OverviewPage").then((module) => ({ default: module.OverviewPage })),
);
const IncidentsPage = lazy(() =>
  import("./pages/IncidentsPage").then((module) => ({ default: module.IncidentsPage })),
);
const AuthenticationPage = lazy(() =>
  import("./pages/AuthenticationPage").then((module) => ({ default: module.AuthenticationPage })),
);
const FirewallPage = lazy(() =>
  import("./pages/FirewallPage").then((module) => ({ default: module.FirewallPage })),
);
const AnalyticsPage = lazy(() =>
  import("./pages/AnalyticsPage").then((module) => ({ default: module.AnalyticsPage })),
);
const AboutPage = lazy(() =>
  import("./pages/AboutPage").then((module) => ({ default: module.AboutPage })),
);

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<LoadingState label="Loading console module" />}>
        <Routes>
          <Route element={<AppShell />}>
            <Route element={<OverviewPage />} index />
            <Route element={<IncidentsPage />} path="incidents" />
            <Route element={<AuthenticationPage />} path="authentication" />
            <Route element={<FirewallPage />} path="firewall" />
            <Route element={<AnalyticsPage />} path="analytics" />
            <Route element={<AboutPage />} path="about" />
          </Route>
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
