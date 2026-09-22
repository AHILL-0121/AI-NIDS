/** The "sonar tick" mark: three arcs and a dot, drawn in the ink colour (design §5.2). */
export function SonarMark({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 20 20"
      fill="none"
      aria-hidden
      className="text-ink"
    >
      <circle cx="4" cy="16" r="1.75" fill="currentColor" />
      <path d="M4 10.5a5.5 5.5 0 0 1 5.5 5.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 6.5a9.5 9.5 0 0 1 9.5 9.5" stroke="currentColor" strokeWidth="1.5" />
      <path d="M4 2.5A13.5 13.5 0 0 1 17.5 16" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}
