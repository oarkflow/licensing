import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { AppLayout } from "@/components/layout";
import { DashboardPage, ProfilePage, LoginPage, SetupPage } from "@/pages";
import { LicensesPage, LicenseDetailPage, LicenseNewPage } from "@/pages/licenses";
import { ClientsPage, ClientDetailPage, ClientNewPage } from "@/pages/clients";
import { ProductsPage, ProductDetailPage, ProductNewPage, ProductEditPage, ProductFeaturesManagerPage } from "@/pages/products";
import { PlanNewPage, PlanDetailPage, PlanEditPage, PlanFeatureAddPage } from "@/pages/plans";
import { FeatureNewPage, FeatureDetailPage, FeatureEditPage } from "@/pages/features";
import { ScopeNewPage, ScopeEditPage } from "@/pages/scopes";
import { AdminUsersPage, AdminUserNewPage, AdminUserEditPage, AdminAPIKeysPage } from "@/pages/admin";
import {
    MessagingProvidersPage,
    MessagingProviderFormPage,
    MessagingTemplatesPage,
    MessagingTemplateFormPage,
    MessagingComposePage,
} from "@/pages/messaging";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            retry: 1,
            refetchOnWindowFocus: false,
        },
    },
});

const App = () => (
    <QueryClientProvider client={queryClient}>
        <AuthProvider>
            <TooltipProvider>
                <Toaster />
                <Sonner />
                <BrowserRouter>
                    <Routes>
                        {/* Public routes */}
                        <Route path="/login" element={<LoginPage />} />
                        <Route path="/setup" element={<SetupPage />} />

                        {/* Protected routes */}
                        <Route element={<AppLayout />}>
                            <Route path="/" element={<Navigate to="/dashboard" replace />} />
                            <Route path="/dashboard" element={<DashboardPage />} />

                            {/* Licenses */}
                            <Route path="/licenses" element={<LicensesPage />} />
                            <Route path="/licenses/new" element={<LicenseNewPage />} />
                            <Route path="/licenses/:id" element={<LicenseDetailPage />} />

                            {/* Clients */}
                            <Route path="/clients" element={<ClientsPage />} />
                            <Route path="/clients/new" element={<ClientNewPage />} />
                            <Route path="/clients/:id" element={<ClientDetailPage />} />

                            {/* Products */}
                            <Route path="/products" element={<ProductsPage />} />
                            <Route path="/products/new" element={<ProductNewPage />} />
                            <Route path="/products/:id" element={<ProductDetailPage />} />
                            <Route path="/products/:id/edit" element={<ProductEditPage />} />
                            <Route path="/products/:productId/features/manage" element={<ProductFeaturesManagerPage />} />

                            {/* Plans */}
                            <Route path="/products/:productId/plans/new" element={<PlanNewPage />} />
                            <Route path="/products/:productId/plans/:planId" element={<PlanDetailPage />} />
                            <Route path="/products/:productId/plans/:planId/edit" element={<PlanEditPage />} />
                            <Route path="/products/:productId/plans/:planId/features/add" element={<PlanFeatureAddPage />} />

                            {/* Features */}
                            <Route path="/products/:productId/features/new" element={<FeatureNewPage />} />
                            <Route path="/products/:productId/features/:featureId" element={<FeatureDetailPage />} />
                            <Route path="/products/:productId/features/:featureId/edit" element={<FeatureEditPage />} />

                            {/* Messaging */}
                            <Route path="/messaging/providers" element={<MessagingProvidersPage />} />
                            <Route path="/messaging/providers/new" element={<MessagingProviderFormPage />} />
                            <Route path="/messaging/providers/:providerId" element={<MessagingProviderFormPage />} />
                            <Route path="/messaging/templates" element={<MessagingTemplatesPage />} />
                            <Route path="/messaging/templates/new" element={<MessagingTemplateFormPage />} />
                            <Route path="/messaging/templates/:templateId" element={<MessagingTemplateFormPage />} />
                            <Route path="/messaging/compose" element={<MessagingComposePage />} />

                            {/* Scopes */}
                            <Route path="/products/:productId/features/:featureId/scopes/new" element={<ScopeNewPage />} />
                            <Route path="/products/:productId/features/:featureId/scopes/:scopeId/edit" element={<ScopeEditPage />} />

                            {/* Admin */}
                            <Route path="/admin/users" element={<AdminUsersPage />} />
                            <Route path="/admin/users/new" element={<AdminUserNewPage />} />
                            <Route path="/admin/users/:id/edit" element={<AdminUserEditPage />} />
                            <Route path="/admin/api-keys" element={<AdminAPIKeysPage />} />

                            {/* Profile */}
                            <Route path="/profile" element={<ProfilePage />} />
                        </Route>

                        {/* Catch-all */}
                        <Route path="*" element={<NotFound />} />
                    </Routes>
                </BrowserRouter>
            </TooltipProvider>
        </AuthProvider>
    </QueryClientProvider>
);

export default App;
