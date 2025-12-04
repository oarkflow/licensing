import { ReactNode } from "react";

interface MenuSectionProps {
  title: string;
  subtitle?: string;
  children: ReactNode;
  image?: string;
}

export const MenuSection = ({ title, subtitle, children, image }: MenuSectionProps) => {
  return (
    <section className="py-10">
      <div className="mb-8 space-y-3">
        <div className="flex items-center gap-5">
          {image && (
            <div className="relative">
              <img 
                src={image} 
                alt={title}
                className="h-20 w-20 rounded-2xl object-cover shadow-md ring-2 ring-primary/10"
              />
              <div className="absolute -bottom-1 -right-1 h-6 w-6 rounded-full bg-primary shadow-sm" />
            </div>
          )}
          <div className="space-y-1">
            <h2 className="text-4xl font-bold tracking-tight text-primary">{title}</h2>
            {subtitle && (
              <p className="text-base font-medium text-secondary">{subtitle}</p>
            )}
          </div>
        </div>
      </div>
      <div className="grid gap-5 md:grid-cols-2 lg:gap-6">
        {children}
      </div>
    </section>
  );
};
