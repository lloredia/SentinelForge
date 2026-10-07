export default function GlitchText({ children, className = '' }) {
  return (
    <span className={`glitch-text ${className}`} data-text={children}>
      {children}
    </span>
  );
}
