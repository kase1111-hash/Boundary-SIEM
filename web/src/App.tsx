import React from "react";
import { Routes, Route } from "react-router-dom";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/Dashboard";
import { AlertListPage, AlertDetailPage } from "./pages/Alerts";
import { EventsPage } from "./pages/Events";
import { RulesPage } from "./pages/Rules";

const App: React.FC = () => (
  <Routes>
    <Route element={<Layout />}>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/alerts" element={<AlertListPage />} />
      <Route path="/alerts/:id" element={<AlertDetailPage />} />
      <Route path="/events" element={<EventsPage />} />
      <Route path="/rules" element={<RulesPage />} />
      <Route
        path="*"
        element={
          <div className="text-center py-12">
            <h2 className="text-xl text-white">Page Not Found</h2>
            <p className="text-gray-400 mt-2">
              The page you are looking for does not exist.
            </p>
          </div>
        }
      />
    </Route>
  </Routes>
);

export default App;
