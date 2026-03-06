import { createBrowserRouter } from "react-router";
import Home from "./pages/Home";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { URLScan } from "./pages/URLScan";
import { EmailScan } from "./pages/EmailScan";
import { DocumentScan } from "./pages/DocumentScan";
import { History } from "./pages/History";
import { Result } from "./pages/Result";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { RootLayout } from "./components/RootLayout";

export const router = createBrowserRouter([
  {
    path: "/",
    element: <RootLayout />,
    children: [
      {
        index: true,
        Component: Home,
      },
      {
        path: "login",
        Component: Login,
      },
      {
        path: "dashboard",
        element: (
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        ),
      },
      {
        path: "scan/url",
        element: (
          <ProtectedRoute>
            <URLScan />
          </ProtectedRoute>
        ),
      },
      {
        path: "scan/email",
        element: (
          <ProtectedRoute>
            <EmailScan />
          </ProtectedRoute>
        ),
      },
      {
        path: "scan/document",
        element: (
          <ProtectedRoute>
            <DocumentScan />
          </ProtectedRoute>
        ),
      },
      {
        path: "history",
        element: (
          <ProtectedRoute>
            <History />
          </ProtectedRoute>
        ),
      },
      {
        path: "result",
        element: (
          <ProtectedRoute>
            <Result />
          </ProtectedRoute>
        ),
      },
    ],
  },
]);