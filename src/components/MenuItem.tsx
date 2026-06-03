import { Badge } from "@/components/ui/badge";

interface MenuItemProps {
  name: string;
  description: string;
  price: string;
  badges?: string[];
}

export const MenuItem = ({ name, description, price, badges }: MenuItemProps) => {
  return (
    <div className="border-y bg-background px-3 py-3 transition-colors hover:bg-muted/60">
      <div className="flex items-start justify-between gap-6">
        <div className="flex-1 space-y-2">
          <div className="space-y-1.5">
            <h3 className="text-sm font-semibold text-foreground">
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
          <p className="text-xs leading-5 text-muted-foreground">
            {description}
          </p>
        </div>
        <div className="flex shrink-0 items-start">
          <span className="text-sm font-semibold text-primary">
            {price}
          </span>
        </div>
      </div>
    </div>
  );
};
