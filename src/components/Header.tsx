import { Phone, Mail, MapPin } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Header = () => {
  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    element?.scrollIntoView({ behavior: "smooth" });
  };

  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/50 bg-card/95 shadow-sm -md supports-[backdrop-filter]:bg-card">
      <div className="container flex h-20 items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-md bg-primary ">
            <span className="text-2xl font-bold text-primary-foreground">F</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-primary md:text-2xl">Fishtail</h1>
            <span className="hidden text-xs font-medium text-secondary md:inline">
              Cuisine of India & Nepal
            </span>
          </div>
        </div>

        <nav className="hidden items-center gap-2 md:flex">
          <Button 
            variant="ghost" 
            className="font-medium transition-colors hover:text-primary"
            onClick={() => scrollToSection("menu")}
          >
            Menu
          </Button>
          <Button 
            variant="ghost" 
            className="font-medium transition-colors hover:text-primary"
            onClick={() => scrollToSection("about")}
          >
            About
          </Button>
          <Button 
            variant="ghost" 
            className="font-medium transition-colors hover:text-primary"
            onClick={() => scrollToSection("contact")}
          >
            Contact
          </Button>
          <Button 
            className="ml-2 bg-primary font-semibold  transition-all hover:scale-105 hover:bg-primary-hover hover:"
            asChild
          >
            <a href="tel:+17203289842">
              <Phone className="mr-2 h-4 w-4" />
              Order Now
            </a>
          </Button>
        </nav>

        <Button 
          className="bg-primary font-semibold  transition-all hover:scale-105 hover:bg-primary-hover md:hidden"
          size="sm"
          asChild
        >
          <a href="tel:+17203289842">
            <Phone className="h-4 w-4" />
          </a>
        </Button>
      </div>
    </header>
  );
};
