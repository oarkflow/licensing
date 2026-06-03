import { Phone, Mail, MapPin, Clock } from "lucide-react";
import { Button } from "@/components/ui/button";

export const Footer = () => {
  return (
    <footer id="contact" className="border-t border-border/50 bg-card">
      <div className="container py-16">
        <div className="grid gap-10 md:grid-cols-2 lg:grid-cols-3">
          <div className="space-y-5">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary">
                <span className="text-2xl font-bold text-primary-foreground">F</span>
              </div>
              <h3 className="text-2xl font-bold text-primary">Fishtail</h3>
            </div>
            <p className="text-base leading-relaxed text-muted-foreground">
              Authentic Indian & Nepali cuisine in Denver, Colorado. 
              Experience the rich flavors and traditional recipes from the Himalayas.
            </p>
          </div>

          <div className="space-y-5">
            <h4 className="text-xl font-bold text-primary">Contact Us</h4>
            <div className="space-y-4">
              <a 
                href="tel:+17203289842"
                className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-primary"
              >
                <Phone className="h-4 w-4" />
                <span>(720) 328-9842</span>
              </a>
              <a 
                href="mailto:fishtail1076@gmail.com"
                className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-primary"
              >
                <Mail className="h-4 w-4" />
                <span>fishtail1076@gmail.com</span>
              </a>
              <a 
                href="https://maps.google.com/?q=1076+N+Ogden+St+Denver+CO+80218"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-2 text-muted-foreground transition-colors hover:text-primary"
              >
                <MapPin className="h-4 w-4" />
                <span>1076 N Ogden St, Denver, CO 80218</span>
              </a>
            </div>
          </div>

          <div className="space-y-5">
            <h4 className="text-xl font-bold text-primary">Hours</h4>
            <div className="flex items-start gap-3 text-muted-foreground">
              <Clock className="mt-1 h-5 w-5 shrink-0 text-primary" />
              <div className="space-y-1 text-base">
                <p className="font-medium">Open Daily</p>
                <p>Dine-in & Takeout Available</p>
                <p className="pt-2 text-sm">Call us for current hours</p>
              </div>
            </div>
            <Button 
              className="w-full bg-primary font-semibold shadow-md transition-all hover:scale-105 hover:bg-primary-hover hover:shadow-lg"
              size="lg"
              asChild
            >
              <a href="tel:+17203289842">
                <Phone className="mr-2 h-5 w-5" />
                Call to Order
              </a>
            </Button>
          </div>
        </div>

        <div className="mt-12 border-t border-border/50 pt-8 text-center text-sm text-muted-foreground">
          <p className="font-medium">© {new Date().getFullYear()} Fishtail Cuisine of India & Nepal. All rights reserved.</p>
          <p className="mt-3 text-xs leading-relaxed">
            The following major food allergens are used as ingredients: Milk, Egg, Fish, Crustacean Shellfish, 
            Tree Nuts, Peanuts, Wheat, Soy, and Sesame. Please notify staff for more information.
          </p>
        </div>
      </div>
    </footer>
  );
};
