import { Header } from "@/components/Header";
import { Hero } from "@/components/Hero";
import { MenuSection } from "@/components/MenuSection";
import { MenuItem } from "@/components/MenuItem";
import { Footer } from "@/components/Footer";
import { menuData } from "@/data/menuData";
import { Separator } from "@/components/ui/separator";
import momosImg from "@/assets/momos.jpg";
import tandooriImg from "@/assets/tandoori.jpg";
import curryImg from "@/assets/curry.jpg";

const Index = () => {
  return (
    <div className="min-h-screen bg-background">
      <Header />
      <Hero />

      <main className="container py-16" id="menu">
        <div className="mb-16 text-center">
          <div className="mb-4 inline-block rounded-full bg-primary/10 px-6 py-2 text-sm font-semibold text-primary">
            Our Complete Menu
          </div>
          <h2 className="mb-4 text-5xl font-bold tracking-tight text-primary md:text-6xl">Discover Our Flavors</h2>
          <p className="mx-auto max-w-2xl text-lg font-medium text-muted-foreground">
            All dishes are made to your taste: Mild, Medium, or Hot
          </p>
          <div className="mx-auto mt-6 h-1 w-24 rounded-full bg-primary"></div>
        </div>

        {/* Appetizers */}
        <MenuSection title="Appetizers" subtitle="Vegetarian">
          {menuData.appetizers.vegetable.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        <MenuSection title="Appetizers" subtitle="Non-Vegetarian" image={tandooriImg}>
          {menuData.appetizers.nonVeg.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Soups & Salads */}
        <MenuSection title="Soups & Salads">
          {menuData.soupsSalads.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Himalayan Specialties */}
        <MenuSection 
          title="From Mt. Everest Base Camp" 
          subtitle="Authentic Himalayan Specialties"
          image={momosImg}
        >
          {menuData.himalayanSpecialties.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Vegetarian Curries */}
        <MenuSection 
          title="Vegetarian Curries" 
          subtitle="Served with Basmati Rice"
          image={curryImg}
        >
          {menuData.vegetarianCurries.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Chicken Curries */}
        <MenuSection title="Chicken Curries" subtitle="Served with Basmati Rice">
          {menuData.chickenCurries.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Lamb & Goat Curries */}
        <MenuSection title="Lamb & Goat Curries" subtitle="Served with Basmati Rice">
          {menuData.lambGoatCurries.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Seafood Curries */}
        <MenuSection title="Seafood Curries" subtitle="Shrimp & Fish - Served with Basmati Rice">
          {menuData.seafoodCurries.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Biryani */}
        <MenuSection title="Biryani" subtitle="Aromatic Long Grain Basmati Rice">
          {menuData.biryani.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Breads - Whole Wheat */}
        <MenuSection title="Whole Wheat Breads" subtitle="Cooked in Clay Oven">
          {menuData.breads.wholeWheat.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Breads - Naan */}
        <MenuSection title="Tandoori Naan" subtitle="Fluffy Flatbreads from Clay Oven">
          {menuData.breads.naan.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Kids Menu */}
        <MenuSection title="Kids Menu" subtitle="For Dining Only">
          {menuData.kidsMenu.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Desserts */}
        <MenuSection title="Desserts">
          {menuData.desserts.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Beverages */}
        <MenuSection title="Beverages">
          {menuData.beverages.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        <Separator className="my-8" />

        {/* Side Orders */}
        <MenuSection title="Side Orders">
          {menuData.sides.map((item, idx) => (
            <MenuItem key={idx} {...item} />
          ))}
        </MenuSection>

        {/* About Section */}
        <section id="about" className="mt-20 overflow-hidden rounded-2xl border border-border bg-card shadow-lg">
          <div className="border-l-4 border-primary p-10 md:p-12">
            <div className="mb-6 inline-block rounded-full bg-primary/10 px-5 py-2 text-sm font-semibold text-primary">
              Our Story
            </div>
            <h2 className="mb-6 text-4xl font-bold text-primary md:text-5xl">About Us</h2>
            <div className="space-y-5 text-base leading-relaxed text-muted-foreground md:text-lg">
              <p>
                Welcome to Fishtail Cuisine of India & Nepal, where we bring the authentic flavors 
                of the Himalayas to Denver, Colorado. Our restaurant specializes in traditional Indian 
                and Nepali cuisine, prepared with time-honored recipes and the finest ingredients.
              </p>
              <p>
                From our signature momos (Nepali dumplings) to our rich, aromatic curries and tandoori 
                specialties cooked in a traditional clay oven, every dish is crafted with care and 
                passion. We offer a wide variety of vegetarian, vegan, and gluten-free options to 
                accommodate all dietary preferences.
              </p>
              <p>
                Experience the warmth of Himalayan hospitality and the rich culinary traditions that 
                have been passed down through generations. Whether you're dining in or taking out, 
                we're committed to providing you with an unforgettable dining experience.
              </p>
            </div>
          </div>
        </section>
      </main>

      <Footer />
    </div>
  );
};

export default Index;
