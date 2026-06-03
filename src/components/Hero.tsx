import { Button } from "@/components/ui/button";
import { MapPin, Phone, Clock } from "lucide-react";
import heroBanner from "@/assets/hero-banner.jpg";

export const Hero = () => {
  return (
    <section className="relative min-h-[650px] w-full overflow-hidden">
      <div 
        className="absolute inset-0 bg-cover bg-center"
        style={{ backgroundImage: `url(${heroBanner})` }}
      >
        <div className="absolute inset-0 bg-black/70" />
      </div>

      <div className="container relative flex min-h-[650px] flex-col items-start justify-center py-24 text-white">
        <div className="max-w-4xl space-y-8">
          <div className="space-y-4">
            <div className="inline-block rounded-full bg-primary px-4 py-2 text-sm font-semibold ">
              Authentic Indian & Nepali Cuisine
            </div>
            <h1 className="text-5xl font-bold leading-[1.1] tracking-tight md:text-6xl lg:text-7xl">
              Fishtail Cuisine of India & Nepal
            </h1>
            <p className="text-xl font-medium text-white/95 md:text-2xl">
              Experience the authentic flavors of the Himalayas in the heart of Denver
            </p>
          </div>

          <div className="flex flex-col gap-4 pt-2 sm:flex-row sm:items-center">
            <Button 
              size="lg" 
              className="bg-primary text-lg font-semibold  transition-all hover:scale-105 hover:bg-primary-hover hover:shadow-xl"
              onClick={() => document.getElementById("menu")?.scrollIntoView({ behavior: "smooth" })}
            >
              View Menu
            </Button>
            <Button 
              size="lg" 
              variant="outline" 
              className="border-2 border-white/30 bg-white/10 text-lg font-semibold text-white  transition-all hover:scale-105 hover:border-white/50 hover:bg-white/20"
              asChild
            >
              <a href="tel:+17203289842">
                <Phone className="mr-2 h-5 w-5" />
                (720) 328-9842
              </a>
            </Button>
          </div>

          <div className="flex flex-col gap-4 border-l-4 border-primary bg-black/30 p-6 ">
            <div className="flex items-start gap-3">
              <MapPin className="mt-1 h-5 w-5 shrink-0 text-primary" />
              <span className="text-lg">1076 N Ogden St, Denver, CO 80218</span>
            </div>
            <div className="flex items-start gap-3">
              <Clock className="mt-1 h-5 w-5 shrink-0 text-primary" />
              <span className="text-lg">Open Daily for Dine-in & Takeout</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
