import { Badge } from "@/components/ui/badge";

interface MenuItemProps {
  name: string;
  description: string;
  price: string;
  badges?: string[];
}

export const MenuItem = ({ name, description, price, badges }: MenuItemProps) => {
  return (
    <div className="group relative overflow-hidden rounded-xl border border-border bg-card p-6 shadow-card transition-all duration-300 hover:border-primary/30 hover:shadow-lg">
      <div className="flex items-start justify-between gap-6">
        <div className="flex-1 space-y-3">
          <div className="space-y-2">
            <h3 className="text-lg font-semibold text-card-foreground transition-colors group-hover:text-primary">
              {name}
            </h3>
            {badges && badges.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {badges.map((badge, idx) => (
                  <Badge 
                    key={idx} 
                    variant="outline"
                    className="border-primary/20 bg-primary/5 text-xs font-medium text-primary"
                  >
                    {badge}
                  </Badge>
                ))}
              </div>
            )}
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground">
            {description}
          </p>
        </div>
        <div className="flex shrink-0 items-start">
          <span className="text-xl font-bold text-primary">
            {price}
          </span>
        </div>
      </div>
      <div className="absolute bottom-0 left-0 h-1 w-0 bg-primary transition-all duration-300 group-hover:w-full" />
    </div>
  );
};
