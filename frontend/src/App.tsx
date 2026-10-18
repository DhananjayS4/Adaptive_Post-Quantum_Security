import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/AppShell";
import { LoadingBlock } from "./components/ui";

const OverviewPage = lazy(() =>
  import("./pages/OverviewPage").then((module) => ({ default: module.OverviewPage })),
);
const PolicyPage = lazy(() =>
  import("./pages/PolicyPage").then((module) => ({ default: module.PolicyPage })),
);
const MessagingPage = lazy(() =>
  import("./pages/MessagingPage").then((module) => ({ default: module.MessagingPage })),
);
const ExperimentsPage = lazy(() =>
  import("./pages/ExperimentsPage").then((module) => ({ default: module.ExperimentsPage })),
);
const FirmwarePage = lazy(() =>
  import("./pages/FirmwarePage").then((module) => ({ default: module.FirmwarePage })),
);

export default function App() {
  return (
    <Suspense fallback={<LoadingBlock />}>
      <Routes>
        <Route element={<AppShell />}>
          <Route index element={<OverviewPage />} />
          <Route path="policy" element={<PolicyPage />} />
          <Route path="messaging" element={<MessagingPage />} />
          <Route path="experiments" element={<ExperimentsPage />} />
          <Route path="firmware" element={<FirmwarePage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </Suspense>
  );
}
