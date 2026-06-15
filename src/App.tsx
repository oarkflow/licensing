import { Suspense, lazy } from "react";
import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { AppLayout } from "@/components/layout";

// Lazy load all page components
const DashboardPage = lazy(() => import("@/pages").then(module => ({ default: module.DashboardPage })));
const ProfilePage = lazy(() => import("@/pages").then(module => ({ default: module.ProfilePage })));
const LoginPage = lazy(() => import("@/pages").then(module => ({ default: module.LoginPage })));
const SetupPage = lazy(() => import("@/pages").then(module => ({ default: module.SetupPage })));

const LicensesPage = lazy(() => import("@/pages/licenses").then(module => ({ default: module.LicensesPage })));
const LicenseDetailPage = lazy(() => import("@/pages/licenses").then(module => ({ default: module.LicenseDetailPage })));
const LicenseNewPage = lazy(() => import("@/pages/licenses").then(module => ({ default: module.LicenseNewPage })));

const ClientsPage = lazy(() => import("@/pages/clients").then(module => ({ default: module.ClientsPage })));
const ClientDetailPage = lazy(() => import("@/pages/clients").then(module => ({ default: module.ClientDetailPage })));
const ClientNewPage = lazy(() => import("@/pages/clients").then(module => ({ default: module.ClientNewPage })));

const SubscriptionsPage = lazy(() => import("@/pages/subscriptions").then(module => ({ default: module.SubscriptionsPage })));

const ProductsPage = lazy(() => import("@/pages/products").then(module => ({ default: module.ProductsPage })));
const ProductDetailPage = lazy(() => import("@/pages/products").then(module => ({ default: module.ProductDetailPage })));
const ProductNewPage = lazy(() => import("@/pages/products").then(module => ({ default: module.ProductNewPage })));
const ProductEditPage = lazy(() => import("@/pages/products").then(module => ({ default: module.ProductEditPage })));
const ProductFeaturesManagerPage = lazy(() => import("@/pages/products").then(module => ({ default: module.ProductFeaturesManagerPage })));

const PlanNewPage = lazy(() => import("@/pages/plans").then(module => ({ default: module.PlanNewPage })));
const PlanDetailPage = lazy(() => import("@/pages/plans").then(module => ({ default: module.PlanDetailPage })));
const PlanEditPage = lazy(() => import("@/pages/plans").then(module => ({ default: module.PlanEditPage })));
const PlanFeatureAddPage = lazy(() => import("@/pages/plans").then(module => ({ default: module.PlanFeatureAddPage })));

const FeatureNewPage = lazy(() => import("@/pages/features").then(module => ({ default: module.FeatureNewPage })));
const FeatureDetailPage = lazy(() => import("@/pages/features").then(module => ({ default: module.FeatureDetailPage })));
const FeatureEditPage = lazy(() => import("@/pages/features").then(module => ({ default: module.FeatureEditPage })));

const ScopeNewPage = lazy(() => import("@/pages/scopes").then(module => ({ default: module.ScopeNewPage })));
const ScopeEditPage = lazy(() => import("@/pages/scopes").then(module => ({ default: module.ScopeEditPage })));

const AdminUsersPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminUsersPage })));
const AdminUserNewPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminUserNewPage })));
const AdminUserEditPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminUserEditPage })));
const AdminAPIKeysPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminAPIKeysPage })));
const AdminSigningKeysPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminSigningKeysPage })));
const AdminCouponsPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminCouponsPage })));
const AdminBillingPage = lazy(() => import("@/pages/admin").then(module => ({ default: module.AdminBillingPage })));

const MessagingProvidersPage = lazy(() => import("@/pages/messaging").then(module => ({ default: module.MessagingProvidersPage })));
const MessagingProviderFormPage = lazy(() => import("@/pages/messaging").then(module => ({ default: module.MessagingProviderFormPage })));
const MessagingTemplatesPage = lazy(() => import("@/pages/messaging").then(module => ({ default: module.MessagingTemplatesPage })));
const MessagingTemplateFormPage = lazy(() => import("@/pages/messaging").then(module => ({ default: module.MessagingTemplateFormPage })));
const MessagingComposePage = lazy(() => import("@/pages/messaging").then(module => ({ default: module.MessagingComposePage })));

const NotFound = lazy(() => import("./pages/NotFound"));

const queryClient = new QueryClient({
    defaultOptions: {
        queries: {
            retry: 1,
            refetchOnWindowFocus: false,
        },
    },
});

// Loading fallback component
const PageLoadingFallback = () => (
    <div className="flex items-center justify-center min-h-screen">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
    </div>
);

const App = () => (
    <QueryClientProvider client={queryClient}>
        <ThemeProvider defaultTheme="system" storageKey="secretr-theme">
            <AuthProvider>
                <TooltipProvider>
                    <Toaster />
                    <Sonner />
                    <BrowserRouter>
                        <Suspense fallback={<PageLoadingFallback />}>
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

                                    {/* Subscriptions */}
                                    <Route path="/subscriptions" element={<SubscriptionsPage />} />

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
                                    <Route path="/admin/signing-keys" element={<AdminSigningKeysPage />} />
                                    <Route path="/admin/coupons" element={<AdminCouponsPage />} />
                                    <Route path="/admin/billing" element={<AdminBillingPage />} />

                                    {/* Profile */}
                                    <Route path="/profile" element={<ProfilePage />} />
                                </Route>

                                {/* Catch-all */}
                                <Route path="*" element={<NotFound />} />
                            </Routes>
                        </Suspense>
                    </BrowserRouter>
                </TooltipProvider>
            </AuthProvider>
        </ThemeProvider>
    </QueryClientProvider>
);

export default App;
