import { useState } from "react";
import { Truck, HardHat, User, Cloud, LogOut, Users, Settings, FileText } from "lucide-react";
import ModeSelector from "@/components/mode-selector";
import SummaryCards from "@/components/summary-cards";
import OperationForm from "@/components/operation-form";
import OperationsHistory from "@/components/operations-history";
import EquipmentModal from "@/components/equipment-modal";
import ExportModal from "@/components/export-modal";
import IntegrationModal from "@/components/integration-modal";
import SignInModal from "@/components/sign-in-modal";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Badge } from "@/components/ui/badge";
import UserManagementModal from "@/components/user-management-modal";

export default function Dashboard() {
  const { toast } = useToast();
  const [currentMode, setCurrentMode] = useState<'delivery' | 'machinery'>('delivery');
  const [showEquipmentModal, setShowEquipmentModal] = useState(false);
  const [showExportModal, setShowExportModal] = useState(false);
  const [showIntegrationModal, setShowIntegrationModal] = useState(false);
  const [showSignInModal, setShowSignInModal] = useState(false);
  const [isUserManagementModalOpen, setIsUserManagementModalOpen] = useState(false);
  const [user, setUser] = useState<{ name: string; email: string; role?: string; subscriptionTier?: string } | null>(null);

  const handleSignIn = (userData: { name: string; email: string }) => {
    setUser(userData);
  };

  const handleSignOut = () => {
    setUser(null);
    toast({
      title: "Signed Out",
      description: "You have been signed out successfully.",
    });
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="bg-primary text-white shadow-lg sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between relative">
            <div className="flex items-center space-x-3">
              <Truck className="text-2xl w-8 h-8" />
              <h1 className="text-xl font-semibold">CarbonCompanion</h1>
            </div>
            <div className="flex items-center space-x-4">
              <button 
                onClick={() => setShowIntegrationModal(true)}
                className="p-2 hover:bg-primary/80 rounded-lg transition-colors"
                title="CarbonConstruct Integration"
              >
                <Cloud className="w-6 h-6" />
              </button>

              {user ? (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm" className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      {user.name}
                      {user.subscriptionTier && (
                        <Badge variant="outline" className="ml-1 text-xs">
                          {user.subscriptionTier}
                        </Badge>
                      )}
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    {(user.role === 'admin' || user.role === 'manager') && (
                      <DropdownMenuItem onClick={() => setIsUserManagementModalOpen(true)}>
                        <Users className="h-4 w-4 mr-2" />
                        User Management
                      </DropdownMenuItem>
                    )}
                    <DropdownMenuItem onClick={() => setShowIntegrationModal(true)}>
                      <Settings className="h-4 w-4 mr-2" />
                      Integrations
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={() => setShowExportModal(true)}>
                      <FileText className="h-4 w-4 mr-2" />
                      Export Data
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={handleSignOut}>
                      Sign Out
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              ) : (
                <Button
                  onClick={() => setShowSignInModal(true)}
                  variant="secondary"
                  size="sm"
                  className="bg-white/10 hover:bg-white/20 text-white border-white/20"
                >
                  <User className="w-4 h-4 mr-2" />
                  Sign In
                </Button>
              )}
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-6 space-y-6">
        <ModeSelector currentMode={currentMode} onModeChange={setCurrentMode} />

        <SummaryCards 
          onExport={() => setShowExportModal(true)}
          onManageEquipment={() => setShowEquipmentModal(true)}
        />

        <OperationForm mode={currentMode} />

        <OperationsHistory onExport={() => setShowExportModal(true)} />

        <EquipmentModal 
          isOpen={showEquipmentModal} 
          onClose={() => setShowEquipmentModal(false)} 
        />

        <ExportModal 
          isOpen={showExportModal} 
          onClose={() => setShowExportModal(false)} 
        />

        <IntegrationModal 
          isOpen={showIntegrationModal} 
          onClose={() => setShowIntegrationModal(false)} 
        />

        <SignInModal 
          isOpen={showSignInModal} 
          onClose={() => setShowSignInModal(false)}
          onSignIn={handleSignIn}
        />

        <UserManagementModal
          isOpen={isUserManagementModalOpen}
          onClose={() => setIsUserManagementModalOpen(false)}
          currentUser={{
            role: user?.role || 'user',
            subscriptionTier: user?.subscriptionTier || 'free'
          }}
        />
      </main>
    </div>
  );
}