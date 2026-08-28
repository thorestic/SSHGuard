import { ChevronLeft, ChevronRight } from "lucide-react";

export function PaginationControls({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (offset: number) => void;
}) {
  const start = total === 0 ? 0 : offset + 1;
  const end = Math.min(offset + limit, total);

  return (
    <div className="pagination">
      <span>{start}–{end} of {total.toLocaleString()}</span>
      <div>
        <button
          aria-label="Previous page"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          type="button"
        ><ChevronLeft size={17} /></button>
        <button
          aria-label="Next page"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          type="button"
        ><ChevronRight size={17} /></button>
      </div>
    </div>
  );
}

